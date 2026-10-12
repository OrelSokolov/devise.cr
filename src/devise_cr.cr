# devise_cr — порт Devise. P0: database_authenticatable + validatable +
# rememberable + registerable (bcrypt with pepper, byte-compatible with the
# gem), session handler (Warden replacement) and the Iteration 6 JWT
# access/refresh pair with rotation. P1: recoverable + confirmable +
# trackable + lockable + timeoutable + Devise::Mailer. Phase H: HTTP-слой
# (devise_for-роуты, контроллеры, хелперы, встроенные вьюхи). P2: GitHub-
# провайдер omniauthable (вместе с Google), test-helpers (Devise::Test::
# IntegrationHelpers: sign_in/sign_out в тестах) и полный i18n (en.yml 1:1,
# Devise.t/t!/load_locale/locale=).

require "active_record_cr"
require "action_mailer_cr"
require "action_pack_cr"
require "./encryptor"
require "./token_generator"
require "./models"
require "./models_p1"
require "./mailer"
require "./sessions"
require "./jwt"
require "./omniauth"
require "./i18n"
require "./http/mappings"
require "./http/routes"
require "./http/helpers"
require "./http/controllers"
require "./http/views"
require "./http/views_generator"
require "./http/omniauth_actions"
require "./test_helpers"
