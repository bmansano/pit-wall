// Supabase Edge Function — anthropic-proxy
// Deploy: Supabase Dashboard → Edge Functions → anthropic-proxy → cole este código → Deploy
// Secret: Edge Functions → Manage secrets → ANTHROPIC_API_KEY = sk-ant-...

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// Deno global — disponível no runtime da Supabase Edge Function
declare const Deno: { env: { get(key: string): string | undefined } };

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS });
  }

  // Always return HTTP 200 — errors go in the body so the SDK doesn't throw
  const ok = (data: unknown) =>
    new Response(JSON.stringify(data), {
      status: 200,
      headers: { ...CORS, "Content-Type": "application/json" },
    });

  const t0 = Date.now();

  try {
    const apiKey = Deno.env.get("ANTHROPIC_API_KEY");
    if (!apiKey) {
      return ok({ error: { message: "ANTHROPIC_API_KEY secret não configurado no Supabase. Vá em Edge Functions → Manage secrets." } });
    }

    const payload = await req.json();

    // Extract metadata for logging (passados opcionalmente pelo frontend)
    const logMeta = {
      setup_id:   payload._setup_id   ?? null,
      user_id:    payload._user_id    ?? null,
      is_followup: payload._is_followup ?? false,
      rag_arm:    payload._rag_arm    ?? "unknown",
      rag_used:   payload._rag_used   ?? false,
    };

    // Strip private meta fields before forwarding to Anthropic
    const { _setup_id, _user_id, _is_followup, _rag_arm, _rag_used, ...anthropicPayload } = payload;

    // Prompt caching: habilitado por padrão nos modelos claude-sonnet-4 e claude-haiku-4-5.
    // Não requer mais o header anthropic-beta (era necessário apenas para Claude 3.x).
    // Thresholds mínimos: Sonnet 4 = 1.024 tokens | Haiku 4.5 = 4.096 tokens.
    // Nosso system prompt (~1.175 tokens) cacheia no Sonnet; Haiku fica abaixo do threshold
    // mas isso é aceitável — follow-ups já são baratos com Haiku.
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(anthropicPayload),
    });

    const data = await res.json();

    // ── Logging estruturado ───────────────────────────────────────────────────
    // Visível em: Supabase Dashboard → Edge Functions → anthropic-proxy → Logs
    const duration_ms = Date.now() - t0;
    const usage = data.usage ?? {};
    console.log(JSON.stringify({
      event:               "anthropic_call",
      ts:                  new Date().toISOString(),
      duration_ms,
      model:               anthropicPayload.model ?? "unknown",
      is_followup:         logMeta.is_followup,
      rag_arm:             logMeta.rag_arm,
      rag_used:            logMeta.rag_used,
      setup_id:            logMeta.setup_id,
      user_id:             logMeta.user_id,
      input_tokens:        usage.input_tokens        ?? 0,
      output_tokens:       usage.output_tokens       ?? 0,
      cache_creation_tokens: usage.cache_creation_input_tokens ?? 0,
      cache_read_tokens:   usage.cache_read_input_tokens      ?? 0,
      // Custo estimado em USD (Haiku: $0.80/MTok in, $4/MTok out; Sonnet: $3/MTok in, $15/MTok out)
      // cache_read cobrado a 10% do preço normal de input
      http_status:         res.status,
    }));

    return ok(data);

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(JSON.stringify({
      event:       "anthropic_call_error",
      ts:          new Date().toISOString(),
      duration_ms: Date.now() - t0,
      error:       msg,
    }));
    return ok({ error: { message: "Erro interno na Edge Function: " + msg } });
  }
});
