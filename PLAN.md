# devise.cr — порт Devise

> ⚠️ EXPERIMENTAL FRAMEWORK, DO NOT USE IN PRODUCTION YET.

Неймспейс: `Devise` — 1:1. Оценка: ~80%. Берётся на Iteration 6,
после стабильного active_record/action_pack/action_view. Цель — Rails-приложение
с девайс-аутентификацией переносилось заменой `Rails→CRails`.

## API 1:1

### Модель
- `devise :database_authenticatable, :registerable, :recoverable,
  :rememberable, :trackable, :validatable, :confirmable, :lockable,
  :timeoutable, :omniauthable` (модули включаются макросом — как в
  Rails, где это `devise_modules`)
- `validatable` = стандартные валидации email/пароля (1:1 к active_record.cr)
- `User.create!`, `update_with_password`, `valid_password?`,
  `send_reset_password_instructions`, `confirm`, `lock_access!` и т.д.
  по модулям

### Роуты и контроллеры
- `devise_for :users (path:, controllers:, path_names:, only:, except:)`
  → `/users/sign_in|sign_up|sign_out|password|confirmation` — те же пути
- Sessions/Registrations/Passwords/Confirmations/Unlocks контроллеры
  (сгенерированные, кастомизируются наследованием — как в Rails)
- Хелперы: `authenticate_user!` (before_action), `user_signed_in?`,
  `current_user`, `user_session`, `require_no_authentication`,
  `after_sign_in_path_for`-хуки

### Конфиг и взгляды
- `config/initializers/devise.cr`: `config.mailer_sender`,
  `config.password_length`, `config.remember_for`, `config.timeout_in`,
  `config.maximum_attempts`, `config.unlock_strategy`,
  `config.pepper`, `config.stretches` — те же имена
- `devise :views` — кастомизируемые ECR-вьюхи
- Mailer: `Devise::Mailer` (confirmation/reset — через action_mailer.cr)
- `secret_key` → pepper/peppering паролей как в Rails

### Аутентификация под капотом
Warden-стэк → `HTTP::Handler`-middleware: сессия → стратегия → failure
app. Хэши паролей: `Crypto::Bcrypt` (stdlib) с pepper-подмешиванием,
cost = stretches. Sessions: cookie_store из railties.cr.
Rememberable: signed cookie + токен-таблица.

## Чего не будет в P0

`omniauthable` (внешние провайдеры — P2, нужны OAuth-клиенты),
`saml`, `devise-otp` и прочие сторонние расширения. Test-helpers
(`sign_in user` в тестах) — были отложены в P1, готовы (см. Статус).

## Статус (Iteration 6 — P0+P1 готовы, oracle 66/66 + omniauth 26+12 + юниты 11, итого 104/104)
- Оракул: `oracle/cases.rb` → `expected.yml` — standalone-харнесс devise
  4.9.4 (AR sqlite), 66 кейсов (26 P0 + 40 P1), повторный прогон
  DETERMINISTIC. Зеркало `spec/oracle_spec.cr` проходит 66/66 без правки
  кейсов.
- Модель: макрос `devise` (src/models.cr) на AR::Base — виртуальные
  password/password_confirmation, `valid_password?`,
  `update_with/without_password`, валидации validation__devise_* (AR-раннер),
  uniqueness через `WHERE LOWER(email) = LOWER(?)`, rememberable
  (authenticatable_salt = ep[0,29], serialize_into/from_cookie),
  registerable (перехват new/create/create! с password-до-save).
- Encryptor: bcrypt (stdlib) с pepper, **byte-compatible с gem'ом**
  (Ruby-хэши rehash-ятся идентично; verified). Отклонение: Crystal-bcrypt
  не хэширует ровно 72 байта (внутр. NUL) → обрезаем до 71 (Ruby до 72);
  различается только пароль ровно в 72 байта.
- Sessions (`src/sessions.cr`): Warden-замена — sign_in/out/signed_in?,
  current_user, authenticate + flash-строки devise en.yml. HTTP-интеграция
  (cookie-сессии action_pack) — P1.
- JWT (`src/jwt.cr`, наш модуль — в Rails его нет): HS256 через
  OpenSSL::HMAC, access {sub,iat,exp,jti} + opaque refresh
  (SHA256-хэш в devise_refresh_tokens), ротация с ревоком,
  TokenInvalid/TokenExpired. Кросс-чек: ruby-jwt-токен декодируется
  тем же secret (фикстура в spec).
- Юниты: `spec/sessions_jwt_spec.cr` — 11 кейсов (flash, session store,
  roundtrip, tamper, wrong secret, expired, кросс-декод, ротация+ревок).
- P1 модели (`src/models_p1.cr`, вторая стадия макроса `devise`):
  - token generator (`src/token_generator.cr`): friendly_token
    (urlsafe_base64 + tr lIO0→sxyz) и digest **байт-совместимый с gem'ом**
    (PBKDF2-HMAC-SHA1 65536/64 salt "Devise <column>" → HMAC-SHA256 hex;
    oracle-кейс tok_digest_fixed сверяет hex на фиксированном raw).
    reset_password_token/unlock_token хранятся digest'ом;
    confirmation_token — RAW (как в 4.9.4), confirm_by_token ищет raw,
    затем digest-fallback.
  - recoverable: send/find/reset по токену, period_valid (6h), очистка
    токена before-update при смене password/email, reset_password_by_token
    (expired/blank/short-пароль не съедает токен), send_reset_password_
    instructions(email) с :not_found.
  - confirmable: токен на create + письмо, confirm (already_confirmed,
    period_expired), confirm_by_token (+blank/invalid), reconfirmable
    (postpone email → unconfirmed_email, регенерация токена, перенос при
    confirm), skip_confirmation!, allow_unconfirmed_access_for,
    active_for_authentication?/inactive_message :unconfirmed.
  - trackable: update_tracked_fields!(Devise::RequestInfo) — count,
    current/last sign_in at+ip (new_record? скипается).
  - lockable: valid_for_authentication? c failed_attempts/maximum_attempts,
    lock_access!/unlock_access!/unlock_access_by_token, lock_expired
    (unlock_in), unauthenticated_message :locked/:last_attempt, стратегии
    lock/unlock (:both).
  - timeoutable: timedout? (Ruby-семантика: nil last_access → nil, nil
    timeout_in → false).
  - класс-конфиги *_within/confirm_within/allow_unconfirmed_access_for/
    maximum_attempts/lock_strategy/unlock_strategy/unlock_in/timeout_in —
    переопределяются на классе (nil-override «прилипает», *_set-флаг).
- Devise::Mailer (`src/mailer.cr`, поверх action_mailer_cr): пять action'ов
  гема с subject-строками en.yml, from: mailer_sender, to: unconfirmed_email
  при reconfirm; доставка — instance-вызов + Base.deliver (сериализация
  ActiveJob-аргов не применяется к немедленной доставке). Заголовки
  сверены оракулом (mail_reset/confirmation/unlock).
- Omniauthable P2 (`src/omniauth.cr`): OmniAuth AuthHash-схема 1:1
  (omniauth 2.1.3: provider/uid/info/credentials/extra, InfoHash#name
  fallback name → "first last" → nickname → email → nil, valid?) +
  google_oauth2-стратегия 1:1 (omniauth-google-oauth2 1.1.1):
  нормализация scope (`email,profile` → `email profile`, префикс
  BASE_SCOPE_URL), authorize-параметры (access_type=offline, state
  hex-48), POST /token + GET userinfo на stdlib HTTP::Client — без
  внешних шардов (готовых omniauth-шардов с AuthHash-контрактом нет;
  multi_auth — другой API). Макрос: `devise :omniauthable,
  omniauth_providers: [...]` → omniauth_providers/devise_modules +
  `from_omniauth(auth)` (генераторная идиома: find по provider+uid, else
  create c friendly_token-паролем). Оракул: `oracle/omniauth_cases.rb` →
  `omniauth_expected.yml` — 26 кейсов, 2 подпроцесса (devise-стеку нужен
  rack >= 3, oauth2 2.0.8 — rack < 3; зеркало `spec/omniauth_spec.cr`
  26/26 + wire-flow юнит (code → token → userinfo → AuthHash против
  локального HTTP-стаба).

**Не в P0 (см. Фазы):** recoverable/confirmable/trackable/lockable/
timeoutable + Devise::Mailer — P1 ✅ (модельная сторона + мейлер; HTTP-роуты
`devise_for`/контроллеры — вместе с railties-сессиями); omniauthable — P2 ✅
(GitHub-провайдер и роуты `/:resource/auth/:provider(/callback)` — вместе с
HTTP-слоем).

## Фазы

- P0: database_authenticatable + registerable + validatable +
  rememberable + sessions (sign_in/out, current_user, flash-сообщения),
  bcrypt с pepper.
- P1: recoverable (reset по email), confirmable, trackable, lockable,
  timeoutable, Devise::Mailer ✅.
- P2: omniauthable (Google/GitHub OAuth2), test-helpers, i18n-полный
  (девайс-словари локалей) ✅ (см. «P2 — GitHub + test-helpers + i18n»).

## Готово, когда

`devise_for :users` + `before_action :authenticate_user!` дают
рабочий sign_up/sign_in/sign_out/reset-password флоу с теми же URL и
flash-сообщениями, что в Rails.

## Зависимости

active_record.cr, action_pack.cr, action_view.cr, action_mailer.cr,
active_support.cr.

## Phase H — HTTP-слой ✅ (2026-10-05)

Оракул: `oracle/http_cases.rb` → `oracle/http_expected.yml` (74 кейса),
снят с devise 4.9.4 в throwaway Rails 8.1.4 app (`tmp/http_app`:
minimal + action_mailer railtie, User со всеми модулями +
omniauthable(google_oauth2), allow_forgery_protection=false, hosts
cleared, test mailer). Кейсы: таблица роутов `devise_for` (имена/
глаголы/пути), register/sign-in/sign-out (303/422 статусы —
responder.error_status 4.9), warden session key `[[id],salt]`,
`remember_user_token` cookie, failure-app (302 + alert), password
reset по raw-токену из письма, confirmation, omniauth passthru 404.
Зеркало `spec/http_oracle_spec.cr` 16/16; полный сюит 120/120.

Реализация `src/http/`:
- `mappings.cr` — Devise::MAPPINGS (compile-time, заполняет макрос
  `devise` в models.cr) + лукап `Devise.mapping(scope)` через
  end-of-program кодген. Class-level операции моделей (find/where/
  new/save/assign_attributes/valid_password?/update_with_password/
  confirm/unlock/сериализация remember-cookie) пробрасываются
  типизированными `Proc(T,R).new`-проками через локальные переменные:
  статический тип `ActiveRecord::Base.class` метаметодов конкретных
  моделей не знает, а прок-литералы в позиции аргумента Crystal-парсер
  не принимает.
- `routes.cr` — `devise_for` в `CRails::Routes::Drawer`: стандартная
  таблица роутов 1:1 (модули из модели), путь-префикс /<scope.pluralize>.
  Отклонение: unlock-роуты рисуются при любом lockable (unlock_strategy
  — рантайм-конфиг модели).
- `helpers.cr` — Warden-lite: session key `warden.user.<scope>.key` =
  JSON `[[id],salt]`; remember cookie `remember_<scope>_token`
  (permanent.signed, payload [key-array, salt, generated_at] JSON-
  строкой — CookiePayload не принимает вложенные массивы);
  current_user/user_signed_in?/authenticate_user!/require_no_
  authentication/after_sign_in_path_for (stored location); helpers
  включены во все контроллеры (reopen ActionController::Base).
- `controllers.cr` — Devise::Sessions/Registrations/Passwords/
  Confirmations/Unlocks/OmniauthCallbacksController (ключ диспетчера
  `devise/<name>`; класс omniauth-контроллера назван
  OmniauthCallbacksController — underscore OmniAuth даёт
  omni_auth_callbacks ≠ роута гема). Рендер `render_page`: app-вьюха
  при наличии, иначе встроенная форма (`views.cr`); статусы/flash из
  en.yml 1:1 с оракулом.
- `views.cr` + `views_generator.cr` — встроенные минимальные формы +
  `Devise::ViewsGenerator.run` (`crails g devise:views`: копирует
  ERB-вьюхи в app/views/devise/**).
- `omniauth_actions.cr` — реестр `Devise::OmniAuth.register_google`
  (provider → GoogleOauth2-клиент; аналог Devise.omniauth_configs),
  request-phase (passthru → redirect на authorize_url, иначе 404) и
  кодген per-provider методов-экшенов (google_oauth2 → def
  google_oauth2); кодген-хук finished определён ПОЗЛЕ action_pack'а,
  поэтому выполняется РАНЬШЕ него и методы успевают в диспетчер.

Отклонения от гема: один скоп на запрос (default_scope, для других —
Devise.current(self, "admin")); trackable-поля не обновляются в
контроллерах автоматически; Rails-internal session keys (session_id/
flash) не воспроизводятся (cookie-session jar); статус 422 при
неверном пароле — re-render формы (как 4.9 с responder.error_status).

В спеке механическая подстановка скопа user→http_user (в одном
бинарнике сюита уже есть top-level `User` модельного оракула);
подстановка задокументирована в шапке spec/http_oracle_spec.cr и
трогает только имена/пути, не поведение.

## Test-helpers — `sign_in user` в тестах ✅ (2026-10-06)

Оракул: `oracle/test_helpers_cases.rb` → `oracle/test_helpers_expected.yml`
(14 кейсов, devise 4.9.4 + warden 1.2.9 в tmp/http_app; тела sign_in/
sign_out — дословно из Devise::Test::IntegrationHelpers поверх
Warden::Test::Helpers login_as/logout; повторный прогон DETERMINISTIC —
sqlite-sequence сбрасывается, id=1). Покрыто: find_scope! по классу/
инстансу, sign_in (warden-ключ в сессии, доступ к закрытой странице,
формат ключа [[Integer]+String и id), require_no_authentication-редирект
уже подписанного, явный scope:, sign_out скопом и ресурсом (ключ исчез,
302 на sign_in). Зеркало `spec/test_helpers_spec.cr` — 1 спек на все
кейсы.

Реализация `src/test_helpers.cr` — `Devise::Test::IntegrationHelpers`:
sign_in(resource, scope: nil) кладёт в сессию контроллера тот же
байт-совместимый warden-ключ `"warden.user.<scope>.key"` = JSON
[[id], authenticatable_salt] (минуя sign-in флоу и валидации — как
login_as гема); sign_out(resource|scope) ключ удаляет; включающий класс
предоставляет `controller` — его Set-Cookie играет роль cookie-джара
интеграционной сессии и переносится в следующий запрос. Скоп ресурса —
`Devise.find_scope` (underscore имени класса, как ключ MAPPINGS).

Отклонения от гема: ControllerHelpers (ActionController::TestCase-
вариант гема) не портирован отдельным модулем — в порте нет minitest-
классов, IntegrationHelpers покрывает контракт; warden-прокси нет.

Спек живёт на собственной таблице th_users (не на http_users!):
Dir.glob компилирует spec-файлы в readdir-порядке, этот спек может
выполниться до http_oracle_spec — общая таблица ломала его фикстуры
(HttpUser.first цеплял чужого юзера). id pinned к 1 (setval
th_users_id_seq под oracle-кейс th_warden_key_id).

## P2 — GitHub + test-helpers + i18n ✅ (2026-10-06)

Сюит целиком — **145/145** (`crystal spec`, повторный прогон зелёный).

### GitHub-провайдер (omniauth-github 2.0.1)

- Вендоринг исходников: `oracle/vendor/omniauth-github-2.0.1/` (на стыке
  вендоренного omniauth-oauth2 1.8.0, rack 2.2.17-мир oauth2 2.0.8 — третья
  subprocess-ветка `github` в `oracle/omniauth_cases.rb`).
- Оракул: 12 кейсов `gh_*` → `oracle/omniauth_expected.yml` (вместе с
  прежними 26 g_/oa_): client_options (site/authorize_url/token_url),
  scope-семантика (default nil, кастом как есть), state hex-48 в сессии,
  полный authorize URL, AuthHash (uid=raw_info.id, email из /user/emails при
  scope user/user:email — primary+verified, иначе raw_info.email; extra =
  raw_info + all_emails + token-scope (null допустим)),
  email_access_allowed? по scope.
- Реализация: `Devise::OmniAuth::GitHub` (`src/omniauth.cr`, stdlib
  HTTP::Client); общий интерфейс `Devise::OmniAuth::Strategy`
  (authorize_url/authenticate) — реестр `src/http/omniauth_actions.cr`
  типизирован им, добавлен `Devise::OmniAuth.register_github(id, secret,
  scope:)`; extra-класс расширен all_emails/scope (scope пишется даже null —
  как гем). Зеркало `spec/omniauth_spec.cr` — 38 oracle-кейсов + wire-flow
  юнит GitHub (код → токен → /user → /user/emails → AuthHash против
  локального HTTP-стаба). Итог 39/39.
- SAML — по-прежнему нет (в геме это отдельный гем omniauth-saml).

### Test-helpers (Devise::Test::IntegrationHelpers)

- Оракул: `oracle/test_helpers_cases.rb` →
  `oracle/test_helpers_expected.yml` — 14 кейсов `th_*` (find_scope,
  warden-ключ формата [[id],salt], подписанный запрос 200,
  require_no_authentication-редирект 302, sign_out удаляет ключ, sign_out
  принимает ресурс). Снят с devise 4.9.4 + warden 1.2.9 в tmp/http_app:
  тела sign_in/sign_out IntegrationHelpers воспроизведены дословно
  (login_as/logout), minitest-обвязка заменена явными вызовами.
- Реализация `src/test_helpers.cr`: `Devise::Test::IntegrationHelpers`
  (sign_in(resource, scope:)/sign_out(resource_or_scope)) — warden-lite
  эквивалент: прямая запись/удаление `warden.user.<scope>.key` в сессии
  контроллера (включающий класс даёт `controller`). Публичный
  `Devise.find_scope(resource)`.
- Зеркало `spec/test_helpers_spec.cr` (скоп th_user на собственной таблице
  th_users — spec-файлы компилируются в readdir-порядке, общая таблица с
  http_oracle_spec ломала бы его фикстуры).

### i18n-полный

- Словарь `src/locales/en.yml` — байт-в-байт config/locales/en.yml гема
  4.9.4 (гем шлёт только en; комьюнити-локали — wiki-конвенция: тот же
  YAML-тре под другим верхним ключом). Запекается в бинарь compile-time
  (read_file).
- `src/i18n.cr`: `Devise.t`/`Devise.t!` (dot-пути; ресурс-префикс-фоллбек
  "user.signed_in"→"signed_in" и "user_subject"→"subject" — default-цепочка
  I18n гема; %{интерполяция}; one/other по count), `Devise.locale=` /
  `Devise.load_locale(path)` (верхний ключ YAML = имя локали, как
  I18n.backend.load_file) / `Devise::I18n.register_yaml(loc, yaml)` —
  boot-time регистрация словаря без файла (аналог railtie
  I18n.load_path.concat; потребитель — шарда ~/myshards/devise_i18n.cr,
  порт devise-i18n 1.16.1: 73 локали, запечённые compile-time, ленивый
  парсинг при первом lookup).
- nil-семантика ruby-I18n: ключ, существующий со значением nil → nil
  (= "Translation missing"), en-фоллбэк не делается; фоллбэк на en —
  только для полностью отсутствующего ключа.
- Все flash/failure/mailer-subject строки контроллеров, хелперов, сессий и
  Devise::Mailer переведены с констант на `Devise.t!` (en-вывод
  байт-совместим с оракулами http/модели; тема письма — subject_for-цепочка
  гема). Константы FLASH_*/INACTIVE_MESSAGES удалены.
- Оракул `oracle/i18n_cases.rb` → `oracle/i18n_expected.yml` — 15 кейсов
  `i18n_*` (полный состав ключей en-дерева devise+errors, flash/failure/
  mailer лукапы, not_saved one/other, полная ru-локаль). Зеркало
  `spec/i18n_spec.cr` (en + ru через load_locale, en-fallback на
  отсутствующий ключ).
- Отклонения от Ruby-I18n: отсутствующий ключ в текущей локали → en-фоллбек
  (Ruby вернул бы "Translation missing"); omniauth-failure flash остался без
  %{reason}-части (порт не знает причину): "Could not authenticate you from
  <Kind>." как раньше.

### Прочее

- `db/schema.yml` + таблица th_users (фикстуры test-helpers-зеркала).
- Порядок спеков: `crystal spec` компилирует spec-файлы в порядке readdir
  (не отсортированном) — спеки не должны делить таблицы между файлами
  (th_users для этого и заведена).
