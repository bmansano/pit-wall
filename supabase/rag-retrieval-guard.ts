// PIT WALL — sign-in guard for Supabase Edge Functions that the app calls (made for rag-retrieval).
//
// WHY: the app calls rag-retrieval with the project's PUBLIC key, and anybody can copy that key from the page. Without
// a guard anyone could call the function and spend its embedding / database budget. This guard lets through only a
// signed-in user whose account is approved (or the administrator), and limits how often each user may call.
//
// HOW TO USE — three steps (nothing else in your function changes):
//   1. Paste this whole file at the top of supabase/functions/rag-retrieval/index.ts, after your existing imports.
//   2. Create the guard once:        const guard = makeGuard(Deno.env, (url, init) => fetch(url, init));
//   3. First thing in your handler:  const denied = await guard(req); if (denied) return denied;
//      (CORS preflight OPTIONS requests pass straight through, so your own CORS code keeps working.)
// The app already sends the signed-in user's token with every rag-retrieval call.
//
// Needs no secrets: SUPABASE_URL and SUPABASE_ANON_KEY are provided by Supabase. Optional secrets (defaults in brackets):
//   ADMIN_EMAIL [bmansano@gmail.com]   GUARD_LIMIT_PER_MIN [30]   GUARD_LIMIT_PER_HOUR [300]
// Works with the gateway's "Verify JWT" switch on or off.

type PwEnv = { get(key: string): string | undefined };
type PwFetch = (url: string, init?: RequestInit) => Promise<Response>;

function makeGuard(env: PwEnv, doFetch: PwFetch) {
  const asks = new Map<string, number[]>();                                      // best effort, per function instance
  const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };

  const num = (k: string, d: number) => { const n = Number(env.get(k)); return Number.isFinite(n) && n > 0 ? Math.floor(n) : d; };
  const refuse = (status: number, message: string, reason: string, extra: Record<string, string> = {}) => {
    console.log(JSON.stringify({ event: "guard_rejected", ts: new Date().toISOString(), reason, status }));
    return new Response(JSON.stringify({ error: { message } }), { status, headers: { ...CORS, "Content-Type": "application/json", ...extra } });
  };
  const wait = (key: string, limit: number, windowMs: number, now: number) => {
    const recent = (asks.get(key) ?? []).filter((t) => now - t < windowMs);
    if (recent.length >= limit) { asks.set(key, recent); return Math.max(1, Math.ceil((windowMs - (now - recent[0])) / 1000)); }
    recent.push(now); asks.set(key, recent); return 0;
  };

  // "ok" with the user id when the token belongs to an approved account (or the administrator); "bad" when Supabase
  // does not accept the token; "no" when the account is not approved.
  async function check(jwt: string): Promise<{ s: "ok"; id: string } | { s: "bad" } | { s: "no" }> {
    const base = (env.get("SUPABASE_URL") ?? "").replace(/\/+$/, ""), anon = env.get("SUPABASE_ANON_KEY") ?? "";
    const h = { apikey: anon, Authorization: "Bearer " + jwt };
    const r = await doFetch(base + "/auth/v1/user", { headers: h });
    if (r.status === 401 || r.status === 403) return { s: "bad" };
    if (!r.ok) throw new Error("auth lookup failed (" + r.status + ")");
    const u = await r.json();
    if (!u || typeof u.id !== "string") return { s: "bad" };
    const email = String(u.email ?? "").toLowerCase();
    const admin = (env.get("ADMIN_EMAIL") ?? "bmansano@gmail.com").trim().toLowerCase();
    if (email !== "" && email === admin && (u.email_confirmed_at || u.confirmed_at)) return { s: "ok", id: u.id };
    const a = await doFetch(base + "/rest/v1/user_approvals?select=status&limit=1&user_id=eq." + encodeURIComponent(u.id), { headers: { ...h, Accept: "application/json" } });
    if (!a.ok) throw new Error("approval lookup failed (" + a.status + ")");
    const rows = await a.json();
    return Array.isArray(rows) && rows[0] && rows[0].status === "approved" ? { s: "ok", id: u.id } : { s: "no" };
  }

  // Returns null when the caller may continue, or the Response to send back.
  return async function guard(req: Request): Promise<Response | null> {
    if (req.method === "OPTIONS") return null;
    const now = Date.now();
    if (!env.get("SUPABASE_URL") || !env.get("SUPABASE_ANON_KEY")) return refuse(500, "SUPABASE_URL / SUPABASE_ANON_KEY are not available to this function.", "no_env");
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "");
    if (!m) return refuse(401, "Your session could not be verified. Reload the page and sign in again.", "no_token");
    let who: { s: "ok"; id: string } | { s: "bad" } | { s: "no" };
    try { who = await check(m[1]); }
    catch (e) {
      console.log(JSON.stringify({ event: "guard_error", ts: new Date().toISOString(), error: e instanceof Error ? e.message : String(e) }));
      return refuse(503, "Could not verify your account right now. Try again in a moment.", "lookup_failed");
    }
    if (who.s === "bad") return refuse(401, "Your session has expired. Sign in again.", "bad_token");
    if (who.s === "no") return refuse(403, "Sign in with an approved account to use this feature.", "not_allowed");
    const s = wait("m:" + who.id, num("GUARD_LIMIT_PER_MIN", 30), 60_000, now) || wait("h:" + who.id, num("GUARD_LIMIT_PER_HOUR", 300), 3_600_000, now);
    if (s) return refuse(429, "Too many requests. Wait " + s + " s and try again.", "rate_limited", { "Retry-After": String(s) });
    return null;
  };
}
