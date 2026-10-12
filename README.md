# devise.cr

A Crystal port of **Devise 4.9.4** — Rails authentication: models,
sessions, controllers/routes, mailer, OmniAuth and test helpers.
Namespace `Devise` mirrors the original 1:1; the Warden stack is replaced
by an `HTTP::Handler`-based warden-lite with byte-compatible session
keys and cookies. Estimated parity ~80%. Suite: **145/145**.

> ⚠️ EXPERIMENTAL FRAMEWORK, DO NOT USE IN PRODUCTION YET.

## Installation

```yaml
dependencies:
  devise_cr:
    github: OrelSokolov/devise.cr
```

```sh
shards install
```

Depends on `active_record.cr`, `action_pack.cr`, `action_view.cr`,
`action_mailer.cr`, `active_support.cr`.

## Usage

```crystal
class User < ActiveRecord::Base
  devise :database_authenticatable, :registerable, :recoverable,
         :rememberable, :trackable, :validatable, :confirmable,
         :lockable, :timeoutable
end

# routes
devise_for :users

# controllers
class ApplicationController < ActionController::Base
  before_action :authenticate_user!   # current_user, user_signed_in?
end
```

## Feature comparison vs devise 4.9.4

### Model modules

| Feature | Original (devise) | Port (devise.cr) | Status |
|---|---|---|---|
| `database_authenticatable` (virtual password/password_confirmation, `valid_password?`, `update_with/without_password`) | ✅ | bcrypt (stdlib) with pepper, **byte-compatible with the gem** (Ruby hashes rehash identically); passwords of exactly 72 bytes are truncated to 71 (Crystal bcrypt NUL quirk) | ✅ |
| `registerable` | ✅ | Intercepts new/create/create! with password-before-save | ✅ |
| `validatable` | ✅ | Standard email/password validations 1:1; uniqueness via `WHERE LOWER(email) = LOWER(?)` | ✅ |
| `rememberable` | ✅ | authenticatable_salt, serialize_into/from_cookie | ✅ |
| `recoverable` | ✅ | Token find/reset, 6 h period, token cleanup, `reset_password_by_token` (expired/blank/short password does not consume the token), `send_reset_password_instructions(email)` with `:not_found` | ✅ |
| `confirmable` | ✅ | Raw token (as in 4.9.4) + digest fallback, reconfirmable (`unconfirmed_email`), `skip_confirmation!`, `active_for_authentication?` | ✅ |
| `trackable` | ✅ | `update_tracked_fields!(Devise::RequestInfo)` — counts, current/last sign_in at+ip | ✅ |
| `lockable` | ✅ | failed_attempts/maximum_attempts, `lock_access!`/`unlock_access_by_token`, lock_expired, `:locked`/`:last_attempt` messages, lock/unlock/:both strategies | ✅ |
| `timeoutable` | ✅ | Ruby-semantics `timedout?` | ✅ |
| `omniauthable` | ✅ | AuthHash schema 1:1 (omniauth 2.1.3), Google (omniauth-google-oauth2 1.1.1) and GitHub (omniauth-github 2.0.1) strategies on stdlib `HTTP::Client`, `from_omniauth(auth)` generator idiom | ✅ |
| Token generator (`friendly_token`, PBKDF2 digest) | ✅ | Byte-compatible digest (PBKDF2-HMAC-SHA1 65536/64, salt `"Devise <column>"` → HMAC-SHA256 hex) | ✅ |
| JWT sessions | not in gem | `src/jwt.cr`: HS256 access + opaque refresh tokens with rotation/revocation (own module, cross-checked against ruby-jwt) | ➕ |

### Routes, controllers & helpers (HTTP layer)

| Feature | Original | Port | Status |
|---|---|---|---|
| `devise_for :users (path:, controllers:, path_names:, only:, except:)` — `/users/sign_in|sign_up|sign_out|password|confirmation` | ✅ | Standard route table 1:1 built from the model's modules; unlock routes drawn for any lockable (unlock_strategy is runtime model config) | 🔶 |
| Sessions/Registrations/Passwords/Confirmations/Unlocks/OmniauthCallbacks controllers, customizable by inheritance | ✅ | `render_page`: app view if present, else built-in form; statuses/flash from en.yml 1:1 | ✅ |
| Warden session key `warden.user.<scope>.key` = `[[id], salt]`, `remember_<scope>_token` cookie | ✅ | Warden-lite over cookie sessions; remember cookie via permanent.signed with a JSON payload | ✅ |
| `authenticate_user!`, `user_signed_in?`, `current_user`, `require_no_authentication`, `after_sign_in_path_for` | ✅ | Same; one scope per request (default scope — others via `Devise.current(self, "admin")`) | 🔶 |
| `Devise::Mailer` (confirmation/reset/unlock) | ✅ | Five gem actions with en.yml subjects via action_mailer.cr; headers oracle-verified | ✅ |
| Views generator | `rails g devise:views` | `Devise::ViewsGenerator.run` (`crails g devise:views`) | ✅ |
| Test helpers: `Devise::Test::IntegrationHelpers` (`sign_in user`, `sign_out`) | ✅ | Byte-compatible warden key written directly into the controller session | ✅ |
| ControllerHelpers (ActionController::TestCase variant) | ✅ | Not ported — IntegrationHelpers covers the contract | ❌ |
| `omniauthable` request/callback routes (`/:resource/auth/:provider(/callback)`) | ✅ | Passthru 404 or redirect to authorize_url; per-provider generated actions | ✅ |
| `saml`, `devise-otp`, other community extensions | ✅ (separate gems) | Not ported | ⬜ |

### Config & i18n

| Feature | Original | Port | Status |
|---|---|---|---|
| `config.mailer_sender/password_length/remember_for/timeout_in/maximum_attempts/unlock_strategy/pepper/stretches` | ✅ | Same names (initializers + class-level `*_within` overrides) | ✅ |
| en.yml dictionary | ✅ | Byte-identical `src/locales/en.yml`; `Devise.t`/`t!` with dot-paths, resource-prefix fallback, `%{}` interpolation, one/other pluralization; `Devise.locale=`/`load_locale` (see devise_i18n.cr for 73 community locales) | ✅ |
| Missing-key semantics | `raise`/"Translation missing" | Falls back to en for fully missing keys (Ruby-I18n nil values still mean "missing") | 🔶 |

## Deviations & Crystal-specific notes

- Model class-level operations go through typed `Proc` bridges and a
  compile-time MAPPINGS registry (no runtime `constantize`).
- Trackable fields are not updated automatically in controllers.
- Rails-internal session keys (session_id/flash internals) are not
  reproduced (cookie-session jar); wrong password renders the form with
  422 (as 4.9 with `responder.error_status`).
- OmniAuth failure flash omits the `%{reason}` part (the port does not
  know the reason).

## Testing

```sh
crystal spec   # 145/145, repeat run green
```

Oracle-first: `oracle/cases.rb` (66 model cases, AR sqlite, devise
4.9.4), `oracle/http_cases.rb` (74 cases recorded in a throwaway Rails
8.1.4 app: route table, register/sign-in/out statuses, warden key,
remember cookie, failure app, password reset by mail token,
confirmation, omniauth passthru), `oracle/omniauth_cases.rb` (26 + 12
Google/GitHub cases), `oracle/test_helpers_cases.rb` (14 cases, devise
4.9.4 + warden 1.2.9), `oracle/i18n_cases.rb` (15 cases) — all replayed
by Crystal mirrors without editing the cases.
