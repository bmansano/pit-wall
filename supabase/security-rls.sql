-- PIT WALL — database security: row-level security (RLS) for every table the app uses.
--
-- WHAT IT DOES
--   • Turns row-level security on for user_approvals, setups, setup_ratings, engineer_memory and car_profiles,
--     and removes every older policy on them (policies add up, so one forgotten "allow all" would defeat the rest).
--   • Anonymous visitors get no access to any of these tables.
--   • A signed-in user must be APPROVED (or be the administrator) to read or write anything: the approval the
--     app shows on screen is now enforced by the database as well.
--   • setups, setup_ratings, engineer_memory: each user sees and changes only their own rows.
--   • setups row "__mods__" (the shared class / car / track lists): approved users read it, only the administrator writes it.
--   • user_approvals: a user reads their own row and can create it as "pending"; only the administrator can
--     approve, reject, revoke or delete.
--   • car_profiles: shared among approved users; removed by their author or the administrator.
--
-- BEFORE YOU RUN IT
--   1. Run supabase/security-audit.sql and keep the result — it shows today's policies, so you can compare.
--   2. Check admin_email inside the "shared" block below (that account must already exist).
--
-- HOW: Supabase → SQL Editor → New query → paste → Run. Safe to run again. The last result lists every table in the
--   public schema and whether it is protected.
--
-- AFTER: sign in as a normal user and as the administrator and check saved setups, rating a setup, the shared
--   lists and approving a user. If the rag-retrieval function reads setups or setup_ratings with the PUBLIC key,
--   switch it to the service-role key (server side only) — row-level security applies to the public key.

begin;

-- >>> shared: administrator and approval helpers (identical in every PIT WALL script — keep them in sync)
-- The administrator is identified by account id, not by a text e-mail: the address is only used once, below,
-- to find the account.
create table if not exists public.app_admins (
  user_id uuid primary key references auth.users (id) on delete cascade
);
alter table public.app_admins enable row level security;
revoke all on table public.app_admins from anon, authenticated;   -- no policies: only the functions below can read it

do $$
declare
  admin_email constant text := 'bmansano@gmail.com';              -- ← the administrator's account (it must already exist)
begin
  insert into public.app_admins (user_id)
    select id from auth.users where lower(email) = lower(admin_email)
    on conflict do nothing;
  if not exists (select 1 from public.app_admins) then
    raise exception 'No account found for % — create it first (sign up in the app) or edit admin_email above, then run this script again.', admin_email;
  end if;
end $$;

create or replace function public.pw_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$ select exists (select 1 from public.app_admins a where a.user_id = auth.uid()) $$;

create or replace function public.pw_is_approved()
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  return public.pw_is_admin()
      or exists (select 1 from public.user_approvals u where u.user_id::text = auth.uid()::text and u.status = 'approved');
end
$$;

revoke all on function public.pw_is_admin(), public.pw_is_approved() from public, anon;
grant execute on function public.pw_is_admin(), public.pw_is_approved() to authenticated;
-- <<< shared

-- 1) The tables the app already uses. "create table if not exists" does nothing when they exist — it only
--    makes this script usable on a brand-new project.
create table if not exists public.user_approvals (
  user_id      uuid primary key references auth.users (id) on delete cascade,
  email        text not null,
  status       text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  requested_at timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create table if not exists public.setups (
  id      text primary key,                                       -- "__mods__" is the shared class / car / track lists
  user_id uuid references auth.users (id) on delete cascade,
  ts      timestamptz not null default now(),
  data    jsonb not null default '{}'::jsonb
);
create table if not exists public.setup_ratings (
  setup_id   text not null,
  user_id    uuid not null references auth.users (id) on delete cascade,
  stars      int  not null check (stars between 1 and 5),
  tag        text,
  created_at timestamptz not null default now(),
  primary key (setup_id, user_id)
);

-- 1b) A saved setup with no owner would become invisible to everybody. The app always saves the owner, but older or
--     hand-made rows might not have one — they are reported here (look at "Messages" in the SQL editor).
do $$
declare n bigint;
begin
  if to_regclass('public.setups') is not null then
    select count(*) into n from public.setups where user_id is null and id::text <> '__mods__';
    if n > 0 then
      raise notice '% saved setup(s) have no owner (user_id is empty) and will not be visible to anyone after this script. List them: select id, ts from public.setups where user_id is null and id <> ''__mods__'';  Give them an owner with an UPDATE.', n;
    end if;
  end if;
end $$;

-- 2) Remove EVERY existing policy on the tables managed here. Policies add up (any one that says "yes" wins),
--    so a forgotten "using (true)" would make all the rules below pointless.
do $$
declare p record;
begin
  for p in
    select tablename, policyname from pg_policies
    where schemaname = 'public'
      and tablename in ('setups', 'setup_ratings', 'user_approvals', 'engineer_memory', 'car_profiles')
  loop
    execute format('drop policy %I on public.%I', p.policyname, p.tablename);
  end loop;
end $$;

-- 3) user_approvals — who may use the app.
--    A user reads their own row and may create it as "pending"; only the administrator approves, rejects,
--    revokes or deletes. (Casting ids to text keeps this working whatever the column type is.)
alter table public.user_approvals enable row level security;
revoke all on table public.user_approvals from anon, authenticated;
grant select, insert, update, delete on table public.user_approvals to authenticated;

create policy pw_approvals_select_own on public.user_approvals
  for select to authenticated
  using (user_id::text = (select auth.uid())::text);
create policy pw_approvals_insert_own_pending on public.user_approvals
  for insert to authenticated
  with check (user_id::text = (select auth.uid())::text
              and status = 'pending'
              and lower(email) = lower(coalesce((select auth.jwt() ->> 'email'), '')));
create policy pw_approvals_update_own_pending on public.user_approvals
  for update to authenticated
  using (user_id::text = (select auth.uid())::text and status = 'pending')
  with check (user_id::text = (select auth.uid())::text
              and status = 'pending'
              and lower(email) = lower(coalesce((select auth.jwt() ->> 'email'), '')));
create policy pw_approvals_admin_all on public.user_approvals
  for all to authenticated
  using ((select public.pw_is_admin()))
  with check ((select public.pw_is_admin()));

-- 4) setups — each approved user sees and changes only their own saved setups.
--    The row with id "__mods__" holds the shared class / car / track lists: approved users read it,
--    only the administrator writes it.
alter table public.setups enable row level security;
revoke all on table public.setups from anon, authenticated;
grant select, insert, update, delete on table public.setups to authenticated;

create policy pw_setups_select_own on public.setups
  for select to authenticated
  using ((select public.pw_is_approved()) and id::text <> '__mods__' and user_id::text = (select auth.uid())::text);
create policy pw_setups_insert_own on public.setups
  for insert to authenticated
  with check ((select public.pw_is_approved()) and id::text <> '__mods__' and user_id::text = (select auth.uid())::text);
create policy pw_setups_update_own on public.setups
  for update to authenticated
  using ((select public.pw_is_approved()) and id::text <> '__mods__' and user_id::text = (select auth.uid())::text)
  with check ((select public.pw_is_approved()) and id::text <> '__mods__' and user_id::text = (select auth.uid())::text);
create policy pw_setups_delete_own on public.setups
  for delete to authenticated
  using (id::text <> '__mods__' and user_id::text = (select auth.uid())::text);

create policy pw_setups_select_lists on public.setups
  for select to authenticated
  using ((select public.pw_is_approved()) and id::text = '__mods__');
create policy pw_setups_admin_write_lists on public.setups
  for all to authenticated
  using ((select public.pw_is_admin()) and id::text = '__mods__')
  with check ((select public.pw_is_admin()) and id::text = '__mods__');

-- 5) setup_ratings — each approved user sees and changes only their own ratings.
alter table public.setup_ratings enable row level security;
revoke all on table public.setup_ratings from anon, authenticated;
grant select, insert, update, delete on table public.setup_ratings to authenticated;

create policy pw_ratings_select_own on public.setup_ratings
  for select to authenticated
  using ((select public.pw_is_approved()) and user_id::text = (select auth.uid())::text);
create policy pw_ratings_insert_own on public.setup_ratings
  for insert to authenticated
  with check ((select public.pw_is_approved()) and user_id::text = (select auth.uid())::text);
create policy pw_ratings_update_own on public.setup_ratings
  for update to authenticated
  using ((select public.pw_is_approved()) and user_id::text = (select auth.uid())::text)
  with check ((select public.pw_is_approved()) and user_id::text = (select auth.uid())::text);
create policy pw_ratings_delete_own on public.setup_ratings
  for delete to authenticated
  using (user_id::text = (select auth.uid())::text);

-- >>> shared: engineer memory (private per user) and car profiles (shared by approved users) — identical in every PIT WALL script
create table if not exists public.engineer_memory (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create table if not exists public.car_profiles (
  id         text primary key,
  game       text not null,
  car        text not null,
  profile    jsonb not null,
  created_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.engineer_memory enable row level security;
alter table public.car_profiles enable row level security;
revoke all on table public.engineer_memory, public.car_profiles from anon, authenticated;
grant select, insert, update, delete on table public.engineer_memory, public.car_profiles to authenticated;

drop policy if exists "engineer_memory_select_own" on public.engineer_memory;
drop policy if exists "engineer_memory_insert_own" on public.engineer_memory;
drop policy if exists "engineer_memory_update_own" on public.engineer_memory;
drop policy if exists "engineer_memory_delete_own" on public.engineer_memory;
create policy "engineer_memory_select_own" on public.engineer_memory
  for select to authenticated using ((select public.pw_is_approved()) and user_id = (select auth.uid()));
create policy "engineer_memory_insert_own" on public.engineer_memory
  for insert to authenticated with check ((select public.pw_is_approved()) and user_id = (select auth.uid()));
create policy "engineer_memory_update_own" on public.engineer_memory
  for update to authenticated using ((select public.pw_is_approved()) and user_id = (select auth.uid()))
  with check ((select public.pw_is_approved()) and user_id = (select auth.uid()));
create policy "engineer_memory_delete_own" on public.engineer_memory
  for delete to authenticated using (user_id = (select auth.uid()));

drop policy if exists "car_profiles_select_approved" on public.car_profiles;
drop policy if exists "car_profiles_insert_approved" on public.car_profiles;
drop policy if exists "car_profiles_update_approved" on public.car_profiles;
drop policy if exists "car_profiles_delete_owner_admin" on public.car_profiles;
create policy "car_profiles_select_approved" on public.car_profiles
  for select to authenticated using ((select public.pw_is_approved()));
create policy "car_profiles_insert_approved" on public.car_profiles
  for insert to authenticated with check ((select public.pw_is_approved()) and created_by = (select auth.uid()));
create policy "car_profiles_update_approved" on public.car_profiles
  for update to authenticated using ((select public.pw_is_approved()))
  with check ((select public.pw_is_approved()) and created_by = (select auth.uid()));
create policy "car_profiles_delete_owner_admin" on public.car_profiles
  for delete to authenticated using (created_by = (select auth.uid()) or (select public.pw_is_admin()));
-- <<< shared

commit;

notify pgrst, 'reload schema';

-- Result: every table in the public schema, whether row-level security is on, and how many policies it has.
-- A table that shows "false" is readable by anyone who has the public API key — turn it on (or tell me which one it is).
select c.relname                                                            as "table",
       c.relrowsecurity                                                     as "row-level security on",
       (select count(*) from pg_policies p
         where p.schemaname = 'public' and p.tablename = c.relname)         as "policies",
       has_table_privilege('anon', c.oid, 'select')                         as "anon can select"
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r', 'p')
order by c.relrowsecurity, c.relname;
