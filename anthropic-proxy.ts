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

  try {
    const apiKey = Deno.env.get("ANTHROPIC_API_KEY");
    if (!apiKey) {
      return ok({ error: { message: "ANTHROPIC_API_KEY secret não configurado no Supabase. Vá em Edge Functions → Manage secrets." } });
    }

    const payload = await req.json();
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    return ok(data);

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return ok({ error: { message: "Erro interno na Edge Function: " + msg } });
  }
});
