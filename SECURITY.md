# PIT WALL — security

PIT WALL is a static page (GitHub Pages) that talks to one Supabase project. There is no server of our own, so the
security of the app is the sum of four things: **what the page does**, **the database rules**, **two Edge Functions**,
and **settings that only exist in the Supabase dashboard**. This file says what is enforced where, in what order to
switch it on, and what is deliberately *not* done.

## At a glance

| Concern | Where it is handled | Needs you |
|---|---|---|
| Passwords stored safely | Supabase Auth keeps only a one-way **bcrypt hash** (`auth.users.encrypted_password`). The app never stores a password; the form keeps it in memory and hands it to Supabase over HTTPS. | Dashboard settings (below) |
| Guessing passwords | Supabase per-IP limits + optional CAPTCHA + optional per-account lockout + a pause in the browser | CAPTCHA and the hook are optional |
| API routes need a signed-in, approved user | `anthropic-proxy.ts` (done in code) and `supabase/rag-retrieval-guard.ts` (paste into the function) | Deploy both |
| Row-level security on every table | `supabase/security-rls.sql` (+ `security-audit.sql` to look first) | Run them |
| Data encrypted | In transit: HTTPS only. At rest: Supabase encrypts disks and backups. Passwords: hashed. | Nothing — see "Encryption" for why there is no extra layer |
| Browser hardening | Content-Security-Policy, escaped rendering, safe CSV, pinned library, https-only | Nothing |

What is public by design: the page source and the Supabase **anon** key in `index.html`. What must never be in the
page or the repository: the Supabase **service_role** key, the Anthropic key (it lives only in the Edge Function
secrets), any token or password. (Last scan: no secret pattern found in any revision of the repository; the key in the page is the `anon` one.)

## 1. Passwords

* **Hashed, not encrypted.** Encryption can be reversed; a hash cannot. Supabase uses bcrypt, so nobody — not even
  the project owner — can read a password. Do not build "encrypted password" columns: that would be a downgrade.
* **In the app:** new passwords (sign-up, reset) must have at least 10 characters, must not be on a list of very common
  passwords (including look-alikes such as `P@ssw0rd`), must not be only digits or one repeated character, and must not
  contain the e-mail name. Signing in never applies these rules, so older accounts keep working.
* **Reset flow:** the link in the e-mail now leads to a "choose a new password" screen; afterwards every *other*
  session of the account is signed out. (Before, the link only signed the person in and no password was ever changed.)
* **Password managers** are supported (`autocomplete` attributes), which is the best way to get unique passwords.
* **Dashboard settings** (Authentication → Sign In / Providers → Email; menu names may differ slightly):
  *Confirm email* ON · *Minimum password length* 10 or more · *Password requirements* (lower/upper/digits/symbols) as
  you prefer · *Prevent use of leaked passwords* ON (reported to need a paid plan — check yours; it checks HaveIBeenPwned) · *Secure password
  change* ON. Keep the client rule (10) and the server rule equal, otherwise the server's message wins.

## 2. Limiting sign-in attempts

No single control is enough, so there are layers:

1. **Supabase per-IP limit** — by default 30 sign-up / sign-in requests per 5 minutes per IP address. Lower it in
   Authentication → Rate Limits if your plan allows. It stops casual guessing, not an attacker who rotates IPs.
2. **CAPTCHA (recommended).** Create a free Cloudflare Turnstile site, then (a) Authentication → Attack Protection →
   enable CAPTCHA with provider *Turnstile* and the secret key, and (b) paste the **site key** (public) into
   `window.PW_TURNSTILE_SITEKEY` at the top of `index.html`. The sign-in, sign-up and reset forms then show the check and
   send its token; Supabase refuses requests without it, *including direct calls that bypass the page*. Do (a) and (b)
   together — enabling only one breaks sign-in. When the site key is empty nothing changes. (Turnstile's script is the
   only third-party script loaded on demand; it runs in the page.)
3. **Per-account lockout (optional, Teams/Enterprise plans only).** `supabase/login-rate-limit-hook.sql`: after 8 wrong
   passwords for an account within 15 minutes, further attempts are refused until the window clears. Supabase offers
   this hook only on those plans. Trade-off: anyone who knows an address can lock that account for up to 15 minutes.
4. **Pause in the browser** — after 5 wrong passwords the button waits 15 s, then 30 s, 1 min … up to 15 min, and it
   survives a reload. This is a courtesy (it stops accidental hammering and explains what is happening); an attacker simply
   ignores it. The real brakes are 1–3.
5. **Approval gate** — a new account can do nothing until the administrator approves it, and that is now enforced by the
   database and by both Edge Functions, not only on screen.

Without CAPTCHA or the hook, the per-IP limit and the quality of the passwords are the only server-side defence against
password guessing.

## 3. API routes

* **`anthropic-proxy.ts`** (Edge Function). Requires `Authorization: Bearer <the signed-in user's token>`, verifies it with
  Supabase Auth, requires an approved account (the administrator is always allowed), allows web search for the
  administrator only, allows only listed models, caps body size / output tokens / messages / images, forwards only known
  fields, rate-limits per user, returns real HTTP status codes, and logs the verified user id and token counts — never
  keys, tokens or e-mail addresses. Secrets and switches are documented at the top of the file. Recommended:
  set `ALLOWED_ORIGINS` to the site address (default is any). `ENFORCE_AUTH=false` is a **temporary rollback only**.
  The administrator is recognised by a *verified* e-mail address (`ADMIN_EMAIL`).
* **`rag-retrieval`** (Edge Function, its source is not in this repository). The app now sends the signed-in user's token
  with every call. To make the function *require* it, paste `supabase/rag-retrieval-guard.ts` at the top of the function and
  add two lines (the file explains how). Until then the function is callable by anyone who has the public key.
* **Gateway "Verify JWT" switch** — both functions check the user themselves, so it can be on or off. The existing
  function runs with it off (the page used to call it with the public key only); leaving it off is fine.
* **Tables (the Data API)** — every call is checked by row-level security, below.

## 4. Row-level security

Run these in the Supabase SQL editor (each file's header explains it as well):

1. `supabase/security-audit.sql` — read-only; lists tables without protection, "allow all" policies, open
   SECURITY DEFINER functions and secret-looking columns. Keep the result.
2. `supabase/security-rls.sql` — idempotent. Turns RLS on for `user_approvals`, `setups`, `setup_ratings`,
   `engineer_memory` and `car_profiles`, **removes every older policy on them** (policies add up, so one forgotten
   "allow all" defeats the rest), and creates the rules below. Its last result lists every public table and whether it is
   protected — anything showing `false` (for example the tables behind `rag-retrieval`) is still open; protect it or tell
   whoever maintains it.
3. `supabase/engineer-memory.sql` is the part of (2) that the app's ADMIN → CLOUD tab shows; running either is enough.

| Table | Who can do what |
|---|---|
| `user_approvals` | A user reads their own row and may create it as `pending` with their own e-mail. Only the administrator approves, rejects, revokes or deletes. Nobody can approve themselves. |
| `setups` | An approved user reads and writes **only their own** rows. The row `__mods__` (shared class / car / track lists) is readable by approved users and writable by the administrator only. |
| `setup_ratings`, `engineer_memory` | Own rows only (approved users). |
| `car_profiles` | Shared among approved users; deleted by the author or the administrator. |
| Anonymous visitors | No access to any of these tables or helper functions. |

* **The administrator** is stored by account id in `app_admins` (found from the e-mail inside the script), not as a text
  address, so a look-alike or unverified e-mail cannot claim it. If the administrator's account is ever re-created,
  run the script again. The script stops with a clear message if that account does not exist.
* **Setups are private.** Before this change the app loaded every row of `setups` without filtering by user, so whether
  drivers could see each other's setups depended on database rules that were not in the repository. They are now private
  by rule, and the app also asks only for the signed-in user's rows. If you want a shared library, that is a deliberate
  feature to design (it also needs owner labels in the interface).
* A saved setup with **no owner** would become invisible; the app always saves one, but the script reports any such row
  (look at "Messages" in the SQL editor).
* If `rag-retrieval` (or anything else) reads `setups` / `setup_ratings` with the *public* key, switch it to the
  service-role key **inside the function** (never in the page) — row-level security applies to the public key.
* Check the result with *Database → Advisors → Security Advisor* in the dashboard, and re-run the audit now and then.

## 5. Encryption

* **In transit:** HTTPS only. GitHub Pages serves the page over HTTPS (keep *Settings → Pages → Enforce HTTPS* ON), the
  page redirects `http://` to `https://` (except on your own computer), the Supabase client is only created for an
  `https://` address, and the Content-Security-Policy allows connections only to Supabase, Wikimedia and (when
  enabled) Turnstile.
* **At rest:** Supabase encrypts the database storage and backups (AES-256, per its security documentation).
* **Passwords:** hashed (bcrypt), see 1.
* **Why there is no extra "encrypt the columns" layer.** The engineer must read a setup, your notes and the lessons in
  plain text to send them to the AI, and the knowledge base is searched on the server. A key kept in the page protects
  nothing (anyone who can read the page reads the key); a key kept in the same database protects only against a stolen raw
  disk, which the platform already covers. Supabase's own guidance is that its encryption at rest is enough for most needs
  and that column-level encryption is an advanced option to use sparingly (its older transparent-column-encryption
  feature is not recommended). If you have a concrete requirement (for example personal notes under a privacy
  regulation), say so — the right design then is an Edge Function that encrypts with a key from its secrets.
* **What personal data exists:** the e-mail address (in Supabase Auth and in `user_approvals`), saved setups (including the
  conversation with the engineer and your notes), engineer memory, ratings, and — in the browser — `pw_memory_*`,
  `pw_profiles`, `pw_last_config`, `pitwall_*` (maps) and the session. Deleting an account in Supabase removes the rows
  that reference it where the tables use `on delete cascade` (the ones this repository creates do); check the older ones.
  On a shared computer, leave "Remember me" off (the session then disappears when the tab closes) and clear the site's data.

## 6. Browser hardening

* **Content-Security-Policy** (a `<meta>` tag, because GitHub Pages cannot send headers): blocks plugins, `<base>`
  hijacking, form posts to other sites and — most importantly — `fetch`/XHR to any host except this site, Supabase,
  Wikimedia (track maps) and Turnstile, so an injected script could not post your session token elsewhere. **It does not stop an
  injected script from running**: the page compiles its JSX in the browser, which needs `unsafe-eval` and inline scripts.
  Keep it the first element after the charset, and change it together with `window.SB_URL` if the project changes.
* **No injection through text.** Everything the engineer or a user writes is escaped before it reaches the page (this
  was a real stored-XSS hole earlier and is covered by a test). Spreadsheet exports (CSV) neutralise cells that would run
  as formulas and double the quotes.
* **Libraries.** `@supabase/supabase-js` is pinned to an exact version (it used to float to the latest). The other scripts
  are pinned by version on public CDNs but carry no integrity hash. The stronger fix is to host them in the repository
  (then the only code that can run is code in this repository) — recommended as a next step. When updating
  supabase-js, change the version in `index.html`, then test sign-in, reset and a generated setup.
* **"Remember me"** now chooses *where the session is stored* (browser storage vs. tab storage) instead of trying to sign
  out when the page unloads (which did not work reliably and signed the person out of every device).

## 7. Switching it on — in this order

1. **Revoke** any token that was ever pasted into a chat, e-mail or file (for example the GitHub token used to publish
   from the assistant), and turn on two-factor sign-in for GitHub and Supabase.
2. **SQL editor:** `security-audit.sql` → read it → `security-rls.sql`. Then sign in as a normal user and as the
   administrator and check: your saved setups, rating a setup, the shared lists, approving a user, generating a setup.
3. **Edge Functions:** deploy `anthropic-proxy.ts` (secret `ANTHROPIC_API_KEY`); add the guard to `rag-retrieval`.
   Tabs that were open before the deploy must be reloaded.
4. **Authentication settings** in the dashboard: section 1 (passwords, confirmations), section 2 (rate limits, CAPTCHA),
   *URL Configuration* (Site URL = the page address; Redirect URLs = only that address), and, if you wish, *Sessions*
   (time-box or inactivity timeout — plan dependent).
5. **Optional:** the lockout hook (Teams/Enterprise).
6. **GitHub:** Pages → Enforce HTTPS; turn on secret scanning with push protection.
7. Re-run `security-audit.sql` after any change to tables or functions.

## 8. Known limits

* Per-user rate limits inside the Edge Functions are best-effort (each function instance counts separately).
* The pause in the browser is not a security control.
* The CSP cannot stop script execution (see 6); the escaping and the tests do.
* GitHub Pages cannot send security headers (`X-Frame-Options`, HSTS preload, …).
* The administrator is shown the admin screens by e-mail address in the page; what the administrator can *do* is enforced by
  the database (by account id) and the functions, not by the page.
* Data is not encrypted per column (see 5).

## Reporting a problem

E-mail the project owner (the address of the administrator account) with what you found and how to reproduce it. Please do not
open a public issue with details.
