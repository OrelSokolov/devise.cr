# Devise::Test::IntegrationHelpers (devise 4.9.4) — sign_in/sign_out в
# тестах, минуя форму входа. Оракул: oracle/test_helpers_cases.rb →
# oracle/test_helpers_expected.yml (devise 4.9.4 + warden 1.2.9 в
# tmp/http_app).
#
# В геме хелперы делегируют Warden::Test::Helpers login_as/logout (на
# следующий запрос); здесь warden-lite-эквивалент — прямая запись/удаление
# warden-ключа сессии контроллера, тот же формат
# `warden.user.<scope>.key` = JSON [[id], authenticatable_salt].
#
# Включающий класс предоставляет `controller` (ActionController::Base с
# живым контекстом): запись сессии персистится Set-Cookie этого контекста,
# cookie переносится в следующий запрос (аналог cookie-джара
# интеграционной сессии Rails):
#
#   include Devise::Test::IntegrationHelpers
#
#   sign_in user          # → controller.session["warden.user.user.key"]
#   sign_out :user        # ключ удалён

module Devise
  module Test
    module IntegrationHelpers
      # Скоп ресурса: underscore имени класса (Devise::Mapping.
      # find_scope! гема; в порту ключ маппинга строится так же в
      # models.cr).
      def self.find_scope(resource : ActiveRecord::Base) : String
        resource.class.name.split("::").last.underscore
      end

      def self.session_key(scope : String) : String
        "warden.user.#{scope}.key"
      end

      # Sign in a resource: mimics Devise::SessionsController#create
      # (без валидаций/trackable — как login_as гема).
      def sign_in(resource : ActiveRecord::Base, scope : String? = nil) : Nil
        sc = scope || IntegrationHelpers.find_scope(resource)
        mapping = Devise.mapping(sc).not_nil!
        controller.session[IntegrationHelpers.session_key(sc)] =
          [[resource.id.not_nil!], Devise.authenticatable_salt(mapping, resource)].to_json
      end

      # Sign out a resource or scope (logout гема).
      def sign_out(resource_or_scope : ActiveRecord::Base | String | Symbol) : Nil
        sc = resource_or_scope.is_a?(String) || resource_or_scope.is_a?(Symbol) ?
             resource_or_scope.to_s : IntegrationHelpers.find_scope(resource_or_scope)
        controller.session.delete(IntegrationHelpers.session_key(sc))
      end

      # Тест-класс предоставляет контроллер, чья сессия играет роль
      # интеграционной сессии (в геме — request/actiondispatch-сессия).
      abstract def controller : ActionController::Base
    end
  end

  # Скоп по ресурсу/классу (публичная утилита — как
  # Devise::Mapping.find_scope!).
  def self.find_scope(resource : ActiveRecord::Base) : String
    Test::IntegrationHelpers.find_scope(resource)
  end
end
