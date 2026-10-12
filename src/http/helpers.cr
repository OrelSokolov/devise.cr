# Devise::Controllers::Helpers — Warden-lite поверх ActionController
# (Phase H). Сессия: ключ "warden.user.<scope>.key" со значением
# [[id], authenticatable_salt] (JSON — зеркалирует формат оракула,
# кейс http_warden_key_format). Rememberable: cookie
# "remember_<scope>_token" (cookies.permanent.signed, payload
# [key-array, salt, generated_at] — сериализация гема
# serialize_into_cookie).
#
# Помощники попадают во все контроллеры (reopen ActionController::Base
# ниже — как Devise.add_controller_helpers в геме).
#
# Отклонения от гема: один скоп на запрос (default_scope "user",
# геттеры current_user/user_signed_in?; для другого скопа — явный
# Devise.current(self, "admin")); warden-менеджера нет — хелперы
# работают напрямую с cookie-session; remember_me!/#forget_me!
# выполняются через assign_attributes (методы модели видны только
# конкретному классу).

require "json"

module Devise
  module Controllers
    module Helpers
      WARDEN_KEY = ->(scope : String) { "warden.user.#{scope}.key" }

      def __devise_mapping : Devise::Mapping
        Devise.mapping(Devise.default_scope).not_nil!
      end

      def __devise_session_key(scope : String = Devise.default_scope) : String
        "warden.user.#{scope}.key"
      end

      # --- сессия/remember -----------------------------------------

      def devise_sign_in(user : ActiveRecord::Base, scope : String = Devise.default_scope,
                         remember : Bool = false) : Nil
        mapping = Devise.mapping(scope).not_nil!
        session[__devise_session_key(scope)] =
          [[user.id.not_nil!], Devise.authenticatable_salt(mapping, user)].to_json
        if remember && mapping.modules.includes?(:rememberable)
          remember_values = {} of String => ::ActiveRecord::Value
          remember_values["remember_created_at"] = Time.utc
          mapping.assign.call(user, remember_values)
          mapping.save_unvalidated.call(user)
          generated_at = "%f" % Time.utc.to_unix_f
          payload = [[user.id.not_nil!],
                     Devise.authenticatable_salt(mapping, user).not_nil!,
                     generated_at].to_json
          cookies.permanent.signed.set("remember_#{scope}_token", payload)
        end
      end

      def devise_sign_out(scope : String = Devise.default_scope) : Nil
        mapping = Devise.mapping(scope)
        session.delete(__devise_session_key(scope))
        if (user = Devise.current(self, scope)) && mapping &&
           mapping.modules.includes?(:rememberable)
          forget_values = {} of String => ::ActiveRecord::Value
          forget_values["remember_created_at"] = nil
          mapping.assign.call(user, forget_values)
          mapping.save_unvalidated.call(user)
        end
        cookies.delete("remember_#{scope}_token")
      end

      def devise_signed_in?(scope : String = Devise.default_scope) : Bool
        !Devise.current(self, scope).nil?
      end

      # --- guard-хелперы -------------------------------------------

      def require_no_authentication : Nil
        return unless devise_signed_in?
        flash["alert"] = Devise.t!("#{Devise.default_scope}.already_authenticated", scope: "devise.failure")
        redirect_to(after_sign_in_path_for(nil), 302)
      end

      def authenticate_user! : Nil
        return if Devise.current(self)
        store_location_for_user
        flash["alert"] = Devise.t!("#{Devise.default_scope}.unauthenticated", scope: "devise.failure")
        redirect_to(__devise_new_session_path, 302)
      end

      def store_location_for_user : Nil
        return unless request.method == "GET"
        session["user.return_to"] = request.path if request.path != "/"
      end

      def after_sign_in_path_for(user : ActiveRecord::Base?) : String
        session.delete("user.return_to") || "/"
      end

      def user_signed_in? : Bool
        devise_signed_in?
      end

      def current_user : ActiveRecord::Base?
        Devise.current(self)
      end

      def __devise_new_session_path : String
        "#{__devise_mapping.path_prefix}/sign_in"
      end
    end
  end

  # Salt для warden-ключа: encrypted_password[0,29] (метод модели
  # authenticatable_salt доступен только на конкретном классе, чтение —
  # через attrs-прок маппинга).
  def self.authenticatable_salt(mapping : Mapping, user : ActiveRecord::Base) : String?
    ep = mapping.attrs.call(user)["encrypted_password"]?.try(&.to_s).to_s
    ep.empty? ? nil : ep[0, 29]
  end

  # Маппинг скопа → модель (default_scope по умолчанию "user").
  class_property default_scope : String = "user"

  # Текущий пользователь контроллера: сначала warden-ключ сессии, при
  # провале — remember-cookie (auto sign-in, оракул-кейс
  # http_remember_auto_sign_in_status). nil для не найденного/просроченного.
  def self.current(controller : ActionController::Base,
                   scope : String = default_scope) : ActiveRecord::Base?
    mapping = Devise.mapping(scope)
    return nil unless mapping

    if (raw = controller.session["warden.user.#{scope}.key"]?)
      begin
        payload = JSON.parse(raw).as_a?
        id = payload.try(&.[0]?).try(&.as_a?).try(&.[0]?)
        if id && (id64 = id.to_s.to_i64?)
          return mapping.find.call(id64)
        end
      rescue JSON::ParseException
      end
    end

    # rememberable fallback
    return nil unless mapping.serialize_from_cookie
    if (cookie_any = controller.cookies.signed["remember_#{scope}_token"]?) &&
       (raw_cookie = cookie_any.as_s?)
      begin
        cookie = JSON.parse(raw_cookie).as_a
        raise IndexError.new("bad remember payload") unless cookie.size == 3
        key = cookie[0].as_a.map { |e| e.to_s.to_i64 }
        token = cookie[1].to_s
        generated_at = cookie[2].to_s
        if (user = mapping.serialize_from_cookie.not_nil!.call(key, token, generated_at))
          controller.session["warden.user.#{scope}.key"] =
            [[user.id.not_nil!], Devise.authenticatable_salt(mapping, user)].to_json
          return user
        else
          controller.cookies.delete("remember_#{scope}_token")
        end
      rescue ex : JSON::ParseException | IndexError
        controller.cookies.delete("remember_#{scope}_token")
      end
    end
    nil
  end
end

# Хелперы доступны всем контроллерам (гем: Devise.add_controller_helpers
# расширяет ApplicationController).
class ActionController::Base
  include Devise::Controllers::Helpers
end
