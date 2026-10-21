-- PIT WALL — cloud storage for the engineer's memory and the shared car profiles.
-- Run once in Supabase → SQL Editor → New query → paste → Run. Safe to run again.

-- 1) Who may use shared data: the admin, or any user whose registration was approved.
create or replace function public.pw_is_approved()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((auth.jwt() ->> 'email') = 'bmansano@gmail.com', false)
      or exists (
        select 1 from public.user_approvals a
        where a.user_id = auth.uid() and a.status = 'approved'
      );
$$;
revoke all on function public.pw_is_approved() from public, anon;
grant execute on function public.pw_is_approved() to authenticated;

-- 2) Engineer memory: one private row per user (lessons + rated reference setups).
create table if not exists public.engineer_memory (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.engineer_memory enable row level security;
grant select, insert, update, delete on public.engineer_memory to authenticated;

drop policy if exists "engineer_memory_select_own" on public.engineer_memory;
drop policy if exists "engineer_memory_insert_own" on public.engineer_memory;
drop policy if exists "engineer_memory_update_own" on public.engineer_memory;
drop policy if exists "engineer_memory_delete_own" on public.engineer_memory;
create policy "engineer_memory_select_own" on public.engineer_memory
  for select to authenticated using (auth.uid() = user_id);
create policy "engineer_memory_insert_own" on public.engineer_memory
  for insert to authenticated with check (auth.uid() = user_id);
create policy "engineer_memory_update_own" on public.engineer_memory
  for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "engineer_memory_delete_own" on public.engineer_memory
  for delete to authenticated using (auth.uid() = user_id);

-- 3) Car parameter profiles (read from the game's setup screens): shared by all approved users.
create table if not exists public.car_profiles (
  id         text primary key,
  game       text not null,
  car        text not null,
  profile    jsonb not null,
  created_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.car_profiles enable row level security;
grant select, insert, update, delete on public.car_profiles to authenticated;

drop policy if exists "car_profiles_select_approved" on public.car_profiles;
drop policy if exists "car_profiles_insert_approved" on public.car_profiles;
drop policy if exists "car_profiles_update_approved" on public.car_profiles;
drop policy if exists "car_profiles_delete_owner_admin" on public.car_profiles;
create policy "car_profiles_select_approved" on public.car_profiles
  for select to authenticated using (public.pw_is_approved());
create policy "car_profiles_insert_approved" on public.car_profiles
  for insert to authenticated with check (public.pw_is_approved() and auth.uid() = created_by);
create policy "car_profiles_update_approved" on public.car_profiles
  for update to authenticated using (public.pw_is_approved()) with check (public.pw_is_approved() and auth.uid() = created_by);
create policy "car_profiles_delete_owner_admin" on public.car_profiles
  for delete to authenticated using (auth.uid() = created_by or (auth.jwt() ->> 'email') = 'bmansano@gmail.com');
