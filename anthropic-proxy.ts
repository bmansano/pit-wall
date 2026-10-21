// Supabase Edge Function — anthropic-proxy
//
// Every Claude call from the app goes through this function. It keeps the Anthropic API key on the server and
// decides who may spend it and on what.
//
// Deploy:  Supabase Dashboard → Edge Functions → anthropic-proxy → paste this file → Deploy
// Secrets (Edge Functions → Manage secrets):
//   ANTHROPIC_API_KEY      required   sk-ant-...
//   SUPABASE_URL, SUPABASE_ANON_KEY   provided automatically by Supabase
// Optional secrets (defaults in brackets):
//   ENFORCE_AUTH           [true]     set to "false" ONLY as a temporary rollback: it turns the sign-in check off
//   ADMIN_EMAIL            [bmansano@gmail.com]   the administrator: skips the approval check and may use web search
//   ALLOWED_MODELS         [claude-sonnet-5,claude-haiku-4-5,claude-sonnet-5-5,claude-haiku-5-5]   comma separated
//   MAX_OUTPUT_TOKENS      [8192]     largest max_tokens a request may ask for
//   MAX_BODY_BYTES         [10485760] largest request body (screenshots included)
//   RATE_LIMIT_PER_MIN     [20]       requests per user per minute (best effort, per function instance)
//   RATE_LIMIT_PER_HOUR    [200]      requests per user per hour (best effort, per function instance)
//   SEARCH_LIMIT_PER_HOUR  [6]        web-search requests per user per hour
//   ALLOWED_ORIGINS        [*]        comma separated list of sites allowed to call this function from a browser
//   UPSTREAM_TIMEOUT_MS    [140000]   how long to wait for Anthropic
//
// What a request must look like:
//   - header "Authorization: Bearer <the signed-in user's access token>" (the app sends it)
//   - the user must be the administrator or have status "approved" in public.user_approvals
//   - JSON body with only: model, max_tokens, system, messages, tools, temperature, stop_sequences
//     (fields starting with "_" are private log metadata and are never forwarded)
//   - "tools" (web search) is for the administrator only

declare const Deno: {
  env: { get(key: string): string | undefined };
  serve(handler: (req: Request) => Response | Promise<Response>): unknown;
};

type Json = Record<string, unknown>;
type Env = { get(key: string): string | undefined };
type Fetch = (url: string, init?: RequestInit) => Promise<Response>;
type Identity = { user: { id: string; email: string }; isAdmin: boolean; approved: boolean };

const DEFAULT_MODELS = ["claude-sonnet-5", "claude-haiku-4-5", "claude-sonnet-5-5", "claude-haiku-5-5"];
const TOP_LEVEL_FIELDS = ["model", "max_tokens", "system", "messages", "tools", "temperature", "stop_sequences"];
const SEARCH_TOOLS = ["web_search_20260209", "web_search_20250305"];
const SEARCH_TOOL_FIELDS = ["type", "name", "max_uses", "allowed_domains", "blocked_domains", "user_location", "cache_control"];
const IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const MAX_TEXT_CHARS = 400_000;
const MAX_MESSAGES = 80;
const MAX_IMAGES_PER_MESSAGE = 10;
const IDENTITY_TTL_MS = 30_000;

function readConfig(env: Env) {
  const int = (k: string, d: number) => { const n = Number(env.get(k)); return Number.isFinite(n) && n > 0 ? Math.floor(n) : d; };
  const list = (k: string, d: string[]) => { const v = env.get(k); const items = v ? v.split(",").map((s) => s.trim()).filter(Boolean) : []; return items.length ? items : d; };
  return {
    enforceAuth: (env.get("ENFORCE_AUTH") ?? "true").trim().toLowerCase() !== "false",
    adminEmail: (env.get("ADMIN_EMAIL") ?? "bmansano@gmail.com").trim().toLowerCase(),
    supabaseUrl: (env.get("SUPABASE_URL") ?? "").replace(/\/+$/, ""),
    anonKey: env.get("SUPABASE_ANON_KEY") ?? "",
    models: list("ALLOWED_MODELS", DEFAULT_MODELS),
    maxOutput: int("MAX_OUTPUT_TOKENS", 8192),
    maxBody: int("MAX_BODY_BYTES", 10 * 1024 * 1024),
    perMinute: int("RATE_LIMIT_PER_MIN", 20),
    perHour: int("RATE_LIMIT_PER_HOUR", 200),
    searchPerHour: int("SEARCH_LIMIT_PER_HOUR", 6),
    origins: list("ALLOWED_ORIGINS", ["*"]),
    upstreamTimeoutMs: int("UPSTREAM_TIMEOUT_MS", 140_000),
  };
}
type Config = ReturnType<typeof readConfig>;

// ── request validation ───────────────────────────────────────────────────────────────────────────
type Checked =
  | { ok: true; payload: Json; meta: Json; usesSearch: boolean }
  | { ok: false; status: number; message: string };
const fail = (message: string, status = 400): Checked => ({ ok: false, status, message });
const isObj = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);
const short = (v: unknown, n = 64) => (typeof v === "string" ? v.replace(/[^\w.:|\- ]/g, "").slice(0, n) : null);

function checkCacheControl(cc: unknown): boolean {
  if (cc === undefined) return true;
  return isObj(cc) && cc.type === "ephemeral" && (cc.ttl === undefined || cc.ttl === "5m" || cc.ttl === "1h");
}

function checkContent(content: unknown, role: string, isAdmin: boolean): string | null {
  if (typeof content === "string") return content.length > MAX_TEXT_CHARS ? "A message is too long." : null;
  if (!Array.isArray(content) || content.length === 0) return "Message content must be text or a list of content blocks.";
  if (content.length > (isAdmin ? 400 : 24)) return "A message has too many content blocks.";
  let images = 0;
  for (const b of content) {
    if (!isObj(b) || typeof b.type !== "string") return "Invalid content block.";
    if (b.type === "text") {
      if (typeof b.text !== "string" || b.text.length > MAX_TEXT_CHARS) return "Invalid text block.";
      if (!checkCacheControl(b.cache_control)) return "Invalid cache_control.";
    } else if (b.type === "image" && role === "user") {
      const s = b.source;
      if (!isObj(s) || s.type !== "base64" || typeof s.media_type !== "string" || !IMAGE_TYPES.includes(s.media_type) || typeof s.data !== "string") return "Images must be base64 JPEG, PNG, GIF or WebP.";
      if (++images > MAX_IMAGES_PER_MESSAGE) return "Too many images in one message.";
    } else if (role === "assistant" && isAdmin && /^[a-z][a-z0-9_]{1,63}$/.test(b.type)) {
      // server-tool blocks (web search) echoed back to resume a paused turn
    } else {
      return "Content block type \"" + String(b.type).slice(0, 40) + "\" is not allowed.";
    }
  }
  return null;
}

function validatePayload(body: unknown, cfg: Config, isAdmin: boolean): Checked {
  if (!isObj(body)) return fail("The request body must be a JSON object.");
  const payload: Json = {};
  for (const k of Object.keys(body)) {
    if (k.startsWith("_")) continue;
    if (!TOP_LEVEL_FIELDS.includes(k)) return fail("Unsupported field \"" + k.slice(0, 40) + "\". Allowed: " + TOP_LEVEL_FIELDS.join(", ") + ".");
    payload[k] = body[k];
  }
  const meta: Json = {
    setup_id: short(body._setup_id), user_id: short(body._user_id, 40), is_followup: body._is_followup === true,
    rag_arm: short(body._rag_arm, 16) ?? "unknown", rag_used: body._rag_used === true,
  };

  const model = payload.model;
  if (typeof model !== "string") return fail("model is required.");
  const modelOk = cfg.models.some((m) => model === m || (model.startsWith(m + "-") && /^\d{8}$/.test(model.slice(m.length + 1))));
  if (!modelOk) return fail("Model \"" + model.slice(0, 60) + "\" is not allowed here. Allowed: " + cfg.models.join(", ") + ".");

  const mt = payload.max_tokens;
  if (typeof mt !== "number" || !Number.isInteger(mt) || mt < 1) return fail("max_tokens must be a positive integer.");
  if (mt > cfg.maxOutput) return fail("max_tokens " + mt + " is above the limit of " + cfg.maxOutput + " set in the proxy (MAX_OUTPUT_TOKENS).");

  const msgs = payload.messages;
  if (!Array.isArray(msgs) || msgs.length === 0) return fail("messages must be a non-empty list.");
  if (msgs.length > MAX_MESSAGES) return fail("Too many messages in one request (limit " + MAX_MESSAGES + ").");
  for (const m of msgs) {
    if (!isObj(m) || (m.role !== "user" && m.role !== "assistant")) return fail("Each message needs a role of \"user\" or \"assistant\".");
    for (const k of Object.keys(m)) if (k !== "role" && k !== "content") return fail("Unsupported field \"" + k.slice(0, 40) + "\" in a message.");
    const e = checkContent(m.content, m.role as string, isAdmin);
    if (e) return fail(e);
  }

  if (payload.system !== undefined) {
    const sys = payload.system;
    if (typeof sys === "string") { if (sys.length > MAX_TEXT_CHARS) return fail("system is too long."); }
    else if (Array.isArray(sys) && sys.length >= 1 && sys.length <= 8) {
      for (const b of sys) {
        if (!isObj(b) || b.type !== "text" || typeof b.text !== "string" || b.text.length > MAX_TEXT_CHARS || !checkCacheControl(b.cache_control)) return fail("system must be text or a list of text blocks.");
        for (const k of Object.keys(b)) if (k !== "type" && k !== "text" && k !== "cache_control") return fail("Unsupported field \"" + k.slice(0, 40) + "\" in system.");
      }
    } else return fail("system must be text or a list of up to 8 text blocks.");
  }

  let usesSearch = false;
  if (payload.tools !== undefined) {
    if (!isAdmin) return fail("Web search is only available to the administrator.", 403);
    const tools = payload.tools;
    if (!Array.isArray(tools) || tools.length === 0 || tools.length > 2) return fail("tools must be a list of up to 2 web search tools.");
    for (const t of tools) {
      if (!isObj(t) || typeof t.type !== "string" || !SEARCH_TOOLS.includes(t.type) || t.name !== "web_search") return fail("Only the web_search tool is allowed.");
      for (const k of Object.keys(t)) if (!SEARCH_TOOL_FIELDS.includes(k)) return fail("Unsupported field \"" + k.slice(0, 40) + "\" in a tool.");
      if (t.max_uses !== undefined && (typeof t.max_uses !== "number" || !Number.isInteger(t.max_uses) || t.max_uses < 1 || t.max_uses > 10)) return fail("max_uses must be between 1 and 10.");
      if (!checkCacheControl(t.cache_control)) return fail("Invalid cache_control.");
    }
    usesSearch = true;
  }

  if (payload.temperature !== undefined && (typeof payload.temperature !== "number" || payload.temperature < 0 || payload.temperature > 1)) return fail("temperature must be between 0 and 1.");
  if (payload.stop_sequences !== undefined) {
    const s = payload.stop_sequences;
    if (!Array.isArray(s) || s.length > 4 || s.some((x) => typeof x !== "string" || x.length === 0 || x.length > 64)) return fail("stop_sequences must be up to 4 short strings.");
  }
  return { ok: true, payload, meta, usesSearch };
}

// ── handler ──────────────────────────────────────────────────────────────────────────────────────
function makeHandler(env: Env, doFetch: Fetch) {
  const identities = new Map<string, { exp: number; value: Identity }>();
  const hits = new Map<string, number[]>();                        // best-effort, per function instance

  function limited(key: string, limit: number, windowMs: number, now: number): number {
    const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (recent.length >= limit) { hits.set(key, recent); return Math.max(1, Math.ceil((windowMs - (now - recent[0])) / 1000)); }
    recent.push(now); hits.set(key, recent);
    return 0;
  }

  function corsHeaders(cfg: Config, origin: string | null): Record<string, string> {
    const h: Record<string, string> = {
      "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Max-Age": "86400",
    };
    if (cfg.origins.includes("*")) h["Access-Control-Allow-Origin"] = "*";
    else { h["Vary"] = "Origin"; if (origin && cfg.origins.includes(origin)) h["Access-Control-Allow-Origin"] = origin; }
    return h;
  }

  async function identify(cfg: Config, jwt: string, now: number): Promise<Identity | null> {
    const cached = identities.get(jwt);
    if (cached && cached.exp > now) return cached.value;
    const auth = { apikey: cfg.anonKey, Authorization: "Bearer " + jwt };
    const r = await doFetch(cfg.supabaseUrl + "/auth/v1/user", { headers: auth });
    if (r.status === 401 || r.status === 403) return null;
    if (!r.ok) throw new Error("auth lookup failed (" + r.status + ")");
    const u = await r.json();
    if (!isObj(u) || typeof u.id !== "string") return null;
    const email = String(u.email ?? "").toLowerCase();
    const isAdmin = email !== "" && email === cfg.adminEmail;
    let approved = isAdmin;
    if (!isAdmin) {
      const a = await doFetch(cfg.supabaseUrl + "/rest/v1/user_approvals?select=status&limit=1&user_id=eq." + encodeURIComponent(u.id), { headers: { ...auth, Accept: "application/json" } });
      if (!a.ok) throw new Error("approval lookup failed (" + a.status + ")");
      const rows = await a.json();
      approved = Array.isArray(rows) && isObj(rows[0]) && rows[0].status === "approved";
    }
    const value: Identity = { user: { id: u.id, email }, isAdmin, approved };
    if (approved) {                                                   // only approved users are remembered: a fresh approval works at once
      if (identities.size > 500) identities.clear();
      identities.set(jwt, { exp: now + IDENTITY_TTL_MS, value });
    }
    return value;
  }

  return async function handler(req: Request): Promise<Response> {
    const t0 = Date.now();
    const cfg = readConfig(env);
    const cors = corsHeaders(cfg, req.headers.get("origin"));
    const reply = (status: number, data: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(data), { status, headers: { ...cors, "Content-Type": "application/json", ...extra } });
    const refuse = (status: number, message: string, reason: string, extra: Record<string, string> = {}, who: string | null = null) => {
      console.log(JSON.stringify({ event: "anthropic_call_rejected", ts: new Date().toISOString(), reason, status, user_id: who }));
      return reply(status, { error: { message } }, extra);
    };

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST") return reply(405, { error: { message: "Use POST." } }, { Allow: "POST, OPTIONS" });

    const apiKey = env.get("ANTHROPIC_API_KEY");
    if (!apiKey) return reply(500, { error: { message: "ANTHROPIC_API_KEY is not set. In Supabase open Edge Functions → Manage secrets and add it." } });

    const declared = Number(req.headers.get("content-length") || 0);
    if (declared > cfg.maxBody) return refuse(413, "The request is too large.", "body_too_large");

    // ── who is calling? ──
    let who: Identity | null = null;
    if (cfg.enforceAuth) {
      if (!cfg.supabaseUrl || !cfg.anonKey) return reply(500, { error: { message: "SUPABASE_URL / SUPABASE_ANON_KEY are not available to this function." } });
      const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "");
      if (!m) return refuse(401, "Sign in to use the engineer.", "no_token");
      try { who = await identify(cfg, m[1], t0); }
      catch (e) {
        console.log(JSON.stringify({ event: "anthropic_call_error", ts: new Date().toISOString(), error: e instanceof Error ? e.message : String(e) }));
        return reply(503, { error: { message: "Could not verify your account right now. Try again in a moment." } });
      }
      if (!who) return refuse(401, "Your session has expired. Sign in again.", "bad_token");
      if (!who.approved) return refuse(403, "Your account is not approved yet.", "not_approved", {}, who.user.id);
      const wait = limited("m:" + who.user.id, cfg.perMinute, 60_000, t0) || limited("h:" + who.user.id, cfg.perHour, 3_600_000, t0);
      if (wait) return refuse(429, "Too many requests. Wait " + wait + " s and try again.", "rate_limited", { "Retry-After": String(wait) }, who.user.id);
    } else {
      console.log(JSON.stringify({ event: "auth_not_enforced", ts: new Date().toISOString(), note: "ENFORCE_AUTH=false — anyone can call this function" }));
    }
    const isAdmin = who ? who.isAdmin : true;                            // with auth off the old behaviour (everything allowed) is kept

    // ── what do they want? ──
    let text: string;
    try { text = await req.text(); } catch (_e) { return refuse(400, "Could not read the request body.", "unreadable_body", {}, who?.user.id ?? null); }
    if (text.length > cfg.maxBody) return refuse(413, "The request is too large.", "body_too_large", {}, who?.user.id ?? null);
    let body: unknown;
    try { body = JSON.parse(text); } catch (_e) { return refuse(400, "The request body is not valid JSON.", "bad_json", {}, who?.user.id ?? null); }
    const checked = validatePayload(body, cfg, isAdmin);
    if (!checked.ok) return refuse(checked.status, checked.message, "invalid_request", {}, who?.user.id ?? null);
    if (who && checked.usesSearch) {
      const wait = limited("s:" + who.user.id, cfg.searchPerHour, 3_600_000, t0);
      if (wait) return refuse(429, "Web search limit reached. Try again in " + Math.ceil(wait / 60) + " min.", "search_rate_limited", { "Retry-After": String(wait) }, who.user.id);
    }

    // ── ask Anthropic ──
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), cfg.upstreamTimeoutMs);
    let res: Response; let data: unknown;
    try {
      res = await doFetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
        body: JSON.stringify(checked.payload),
        signal: ctl.signal,
      });
      data = await res.json();
    } catch (e) {
      const timedOut = ctl.signal.aborted;
      console.log(JSON.stringify({ event: "anthropic_call_error", ts: new Date().toISOString(), duration_ms: Date.now() - t0, timed_out: timedOut, user_id: who?.user.id ?? null, error: e instanceof Error ? e.name : "error" }));
      return reply(timedOut ? 504 : 502, { error: { message: timedOut ? "The engineer took too long to answer. Try again." : "Could not reach the AI service. Try again in a moment." } });
    } finally { clearTimeout(timer); }

    const usage = isObj(data) && isObj(data.usage) ? data.usage : {};
    const searches = isObj(usage.server_tool_use) ? usage.server_tool_use.web_search_requests : 0;
    console.log(JSON.stringify({
      event: "anthropic_call", ts: new Date().toISOString(), duration_ms: Date.now() - t0,
      model: checked.payload.model, user_id: who ? who.user.id : checked.meta.user_id, admin: isAdmin,
      is_followup: checked.meta.is_followup, rag_arm: checked.meta.rag_arm, rag_used: checked.meta.rag_used, setup_id: checked.meta.setup_id,
      web_search: checked.usesSearch, web_search_requests: searches ?? 0,
      input_tokens: usage.input_tokens ?? 0, output_tokens: usage.output_tokens ?? 0,
      cache_creation_tokens: usage.cache_creation_input_tokens ?? 0, cache_read_tokens: usage.cache_read_input_tokens ?? 0,
      http_status: res.status,
    }));

    if (res.status === 401 || res.status === 403) {
      return reply(502, { error: { message: "The AI service rejected this server's API key. The administrator must check the ANTHROPIC_API_KEY secret." } });
    }
    const extra: Record<string, string> = {};
    const retry = res.headers.get("retry-after"); if (retry) extra["Retry-After"] = retry;
    return reply(res.status, data, extra);
  };
}

Deno.serve(makeHandler(Deno.env, (url, init) => fetch(url, init)));
