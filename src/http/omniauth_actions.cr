# OmniAuth-интеграция HTTP-слоя:
#   1. Реестр сконфигурированных стратегий (provider → клиент) — аналог
#      Devise.omniauth_configs. Бандled стратегии:
#        Devise::OmniAuth.register_google("client-id", "client-secret")
#        Devise::OmniAuth.register_github("client-id", "client-secret",
#                                         scope: "user")
#   2. End-of-program кодген методов-экшенов OmniauthCallbacksController
#      per-provider (google_oauth2 → def google_oauth2; список
#      провайдеров известен только после парсинга моделей; хук finished
#      определён ПОСЛЕ action_pack-кодгена, поэтому выполняется раньше
#      него — методы успевают попасть в диспетчер экшенов).

module Devise
  module OmniAuth
    # provider name → OAuth2-клиент (GoogleOauth2, GitHub).
    @@provider_clients = {} of String => Devise::OmniAuth::Strategy

    def self.register_google(client_id : String, client_secret : String) : Nil
      @@provider_clients["google_oauth2"] = GoogleOauth2.new(client_id, client_secret)
    end

    def self.register_github(client_id : String, client_secret : String,
                             scope : String? = nil) : Nil
      @@provider_clients["github"] = GitHub.new(client_id, client_secret, scope)
    end

    def self.provider_client(provider : String) : Strategy?
      @@provider_clients[provider]?
    end
  end
end

macro finished
  # Методы-экшены callback-фаз по провайдерам всех mappings (уникальные
  # имена; omniauth_callback(provider) — общий код callback-фазы).
  class ::Devise::OmniauthCallbacksController
    {% provider_names = [] of String %}
    {% for m in Devise::MAPPINGS %}
      {% for p in m[:providers] %}
        {% pname = p.stringify %}
        {% unless provider_names.includes?(pname) %}
          {% provider_names << pname %}
          def {{ p.id }} : Nil
            omniauth_callback({{ pname }})
          end
        {% end %}
      {% end %}
    {% end %}
  end
end
