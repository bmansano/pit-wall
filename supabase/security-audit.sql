-- PIT WALL — security audit (read-only: it changes nothing).
-- Supabase → SQL Editor → New query → paste → Run. Each row of the result is one finding.
-- Keep the result: it is the record of how the database was configured before the security script.

with tbl as (
  select c.oid, c.relname, c.relrowsecurity as rls
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind in ('r', 'p')
),
findings as (
  -- tables where anyone with the public key may be able to read everything
  select 'HIGH' as severity, 'RLS' as area, 'public.' || t.relname as object,
         'Row-level security is OFF'
           || case when has_table_privilege('anon', t.oid, 'select') then ' — anonymous visitors can read this table' else '' end as finding
  from tbl t
  where not t.rls

  union all
  -- policies that open a table to everyone, or to every row
  select case when 'anon'::name = any (p.roles) or 'public'::name = any (p.roles) then 'HIGH' else 'MEDIUM' end,
         'POLICY',
         'public.' || p.tablename || ' · ' || p.policyname,
         p.cmd || ' for ' || array_to_string(p.roles, ',') || ' — '
           || case when coalesce(p.qual, '') in ('true', '(true)') or coalesce(p.with_check, '') in ('true', '(true)')
                   then 'allows EVERY row' else 'applies to anonymous / public visitors' end
  from pg_policies p
  where p.schemaname = 'public'
    and ('anon'::name = any (p.roles) or 'public'::name = any (p.roles)
         or coalesce(p.qual, '') in ('true', '(true)') or coalesce(p.with_check, '') in ('true', '(true)'))

  union all
  -- row-level security on but nothing allowed: fine if only server code uses the table
  select 'INFO', 'RLS', 'public.' || t.relname, 'Row-level security is on and there are NO policies — only the service role can use this table (fine if that is intended)'
  from tbl t
  where t.rls and not exists (select 1 from pg_policies p where p.schemaname = 'public' and p.tablename = t.relname)

  union all
  -- functions that run with the owner's rights and can be called by anyone
  select 'HIGH', 'FUNCTION',
         'public.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'SECURITY DEFINER and callable by anonymous visitors — it bypasses row-level security'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef and has_function_privilege('anon', p.oid, 'execute')

  union all
  -- views run with their owner's rights unless created with security_invoker
  select 'MEDIUM', 'VIEW', 'public.' || c.relname,
         'View bypasses row-level security unless it was created WITH (security_invoker = true)'
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'v'
    and not coalesce((select o.option_value = 'true' from pg_options_to_table(c.reloptions) o where o.option_name = 'security_invoker'), false)
    and (has_table_privilege('anon', c.oid, 'select') or has_table_privilege('authenticated', c.oid, 'select'))

  union all
  -- columns that look like they hold secrets
  select 'MEDIUM', 'COLUMN', 'public.' || c.table_name || '.' || c.column_name,
         'The name suggests a secret — passwords, keys and tokens must never be stored as plain text'
  from information_schema.columns c
  where c.table_schema = 'public'
    and c.column_name ~* '(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key)'

  union all
  -- the full policy inventory, for the record
  select 'INFO', 'POLICY-LIST', 'public.' || p.tablename || ' · ' || p.policyname,
         p.cmd || ' for ' || array_to_string(p.roles, ',') || ' · using ' || coalesce(p.qual, '-') || ' · check ' || coalesce(p.with_check, '-')
  from pg_policies p
  where p.schemaname = 'public'
)
select severity, area, object, finding
from findings
order by case severity when 'HIGH' then 1 when 'MEDIUM' then 2 else 3 end, area, object;
