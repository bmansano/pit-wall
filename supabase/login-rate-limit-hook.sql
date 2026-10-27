-- PIT WALL — limit wrong-password attempts per account (Supabase Auth "Password verification attempt" hook).
--
-- AVAILABILITY: Supabase offers this hook on the Teams and Enterprise plans only. On Free or Pro do not use this
-- file: use CAPTCHA, the per-IP rate limits and a strong password policy instead (see SECURITY.md).
--
-- WHAT IT DOES: after 8 wrong passwords for the same account within 15 minutes, every further sign-in attempt for that
-- account is refused until the window clears — even with the right password — so nobody can keep guessing. A correct
-- sign-in below the limit clears the counter.
-- TRADE-OFF: anyone who knows an e-mail address can lock that account out for up to 15 minutes. That is the price of
-- any lockout; the limits are deliberately mild. The owner can still reset the password by e-mail.
--
-- HOW: Supabase → SQL Editor → paste → Run. Then Authentication → Hooks → "Password verification attempt" →
-- Postgres function → public.hook_password_verification_attempt → enable.

begin;

create table if not exists public.auth_login_failures (
  id      bigint generated always as identity primary key,
  user_id uuid not null,
  at      timestamptz not null default now()
);
create index if not exists auth_login_failures_user_at on public.auth_login_failures (user_id, at desc);
create index if not exists auth_login_failures_at on public.auth_login_failures (at);

alter table public.auth_login_failures enable row level security;           -- no policies: the API cannot read or write it
revoke all on table public.auth_login_failures from public, anon, authenticated;

create or replace function public.hook_password_verification_attempt(event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  uid          uuid;
  was_valid    boolean;
  recent       int;
  max_failures constant int := 8;
  win          constant interval := interval '15 minutes';
begin
  uid := nullif(event ->> 'user_id', '')::uuid;
  was_valid := coalesce((event ->> 'valid')::boolean, false);
  if uid is null then
    return jsonb_build_object('decision', 'continue');
  end if;

  delete from public.auth_login_failures where at < now() - interval '1 day';   -- housekeeping

  select count(*) into recent from public.auth_login_failures where user_id = uid and at > now() - win;
  if recent >= max_failures then
    return jsonb_build_object(
      'decision', 'reject',
      'message', 'Too many failed sign-in attempts. Try again in 15 minutes, or reset your password.',
      'should_logout_user', false
    );
  end if;

  if was_valid then
    delete from public.auth_login_failures where user_id = uid;                   -- a correct password clears the slate
  else
    insert into public.auth_login_failures (user_id) values (uid);
  end if;
  return jsonb_build_object('decision', 'continue');
exception when others then
  return jsonb_build_object('decision', 'continue');                              -- never lock everyone out because of a bug here
end
$$;

grant usage on schema public to supabase_auth_admin;
revoke all on function public.hook_password_verification_attempt(jsonb) from public, anon, authenticated;
grant execute on function public.hook_password_verification_attempt(jsonb) to supabase_auth_admin;

commit;
