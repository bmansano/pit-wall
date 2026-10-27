-- PIT WALL — cloud storage for the engineer's memory and the shared car profiles.
-- Run once in Supabase → SQL Editor → New query → paste → Run. Safe to run again.
-- (The same script is shown in the app under ADMIN → CLOUD. supabase/security-rls.sql contains it too.)

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
