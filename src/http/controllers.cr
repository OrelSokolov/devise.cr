# Devise-контроллеры (Phase H) — порт app/controllers/devise/* гема
# 4.9.4. Роуты: "devise/sessions#new" → Devise::SessionsController
# (кодген action_pack маппит Devise::SessionsController → ключ
# "devise/sessions" и вьюдир app/views/devise/sessions — как в Rails).
#
# Поведение сверено оракулом oracle/http_expected.yml: статусы
# (303 после POST-экшенов — responder.error_status, 422 при ошибке
# валидации), Location, flash-строки en.yml.
#
# Отклонения от гема:
#   * вместо respond_with — явные redirect/render;
#   * trackable-поля не обновляются автоматически (update_tracked_fields
#     вызывается приложением);
#   * рендер вьюх — render_page: app-шаблон при наличии, иначе
#     встроенная минимальная форма (Views.fallback).

module Devise

  # Flash-строки — Devise.t (словарь en.yml 1:1 с гемом: src/locales/en.yml;
  # другие локали — Devise.load_locale + Devise.locale=).

  abstract class DeviseController < ActionController::Base
    @resource : ActiveRecord::Base?

    def resource : ActiveRecord::Base?
      @resource
    end

    def resource=(user : ActiveRecord::Base?)
      @resource = user
    end

    def resource_class : ActiveRecord::Base.class
      __devise_mapping.klass
    end

    # Рендер app-вьюхи при наличии, иначе встроенная форма.
    def render_page(action : String, status : Int32 | Symbol = 200) : Nil
      content = begin
        __render_view(action).to_s
      rescue e : ActionController::RoutingError
        nil
      end
      if content
        @performed = true
        response.status_code = status.is_a?(Int32) ? status : __status_int(status)
        body = __layout?(action) ? __render_layout { content } : content
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        __verify_same_origin_request
        response.print body
      else
        render html: Devise::Views.fallback(action, self), status: status
      end
    end

    private def __status_int(status : Symbol) : Int32
      case status
      when :ok                  then 200
      when :unprocessable_content, :unprocessable_entity then 422
      when :see_other           then 303
      else
        raise ArgumentError.new("unsupported status symbol: #{status}")
      end
    end

    def nested_param(root : String, key : String) : String?
      params[root]?.as?(ActionController::Parameters)
        .try(&.[key]?.try(&.to_s))
    end

    private def __devise_inactive_message(user : ActiveRecord::Base,
                                          mapping : Mapping) : String?
      return nil unless mapping.modules.includes?(:confirmable) ||
                       mapping.modules.includes?(:lockable)
      attrs = mapping.attrs.call(user)
      if mapping.modules.includes?(:lockable) && attrs["locked_at"]?
        return Devise.t!("#{mapping.scope}.locked", scope: "devise.failure")
      end
      if mapping.modules.includes?(:confirmable) && !attrs["confirmed_at"]?
        return Devise.t!("#{mapping.scope}.unconfirmed", scope: "devise.failure")
      end
      nil
    end
  end

  class SessionsController < DeviseController
    before_action :require_no_authentication, only: [:new]

    def new
      render_page("new")
    end

    def create
      mapping = __devise_mapping
      email = nested_param("user", "email").to_s
      password = nested_param("user", "password").to_s
      remember = nested_param("user", "remember_me") == "1"

      user = mapping.find_by_email.call(email)
      if user && mapping.valid_password.call(user, password)
        if (message = __devise_inactive_message(user, mapping))
          flash["alert"] = message
          redirect_to(__devise_new_session_path, 302)
        else
          devise_sign_in(user, remember: remember)
          flash["notice"] = Devise.t!("#{__devise_mapping.scope}.signed_in", scope: "devise.sessions")
          redirect_to(after_sign_in_path_for(user), 303)
        end
      else
        flash.now("alert", Devise.t!("#{__devise_mapping.scope}.invalid", scope: "devise.failure", authentication_keys: "Email"))
        render_page("new", status: 422)
      end
    end

    def destroy
      devise_sign_out
      flash["notice"] = Devise.t!("#{__devise_mapping.scope}.signed_out", scope: "devise.sessions")
      redirect_to(after_sign_in_path_for(nil), 303)
    end
  end

  class RegistrationsController < DeviseController
    before_action :authenticate_user!, only: [:edit, :update, :destroy]
    before_action :require_no_authentication, only: [:new, :create, :cancel]

    def new
      @resource = __devise_mapping.build.call({} of String => ::ActiveRecord::Value)
      render_page("new")
    end

    def create
      mapping = __devise_mapping
      values = {} of String => ::ActiveRecord::Value
      {"email", "password", "password_confirmation"}.each do |key|
        if (v = nested_param("user", key))
          values[key] = v
        end
      end
      user = mapping.build.call(values)
      @resource = user
      if mapping.save_validated.call(user)
        if mapping.modules.includes?(:confirmable)
          flash["notice"] = Devise.t!("#{__devise_mapping.scope}.signed_up_but_unconfirmed", scope: "devise.registrations")
        else
          devise_sign_in(user)
          flash["notice"] = Devise.t!("#{__devise_mapping.scope}.signed_up", scope: "devise.registrations")
        end
        redirect_to(after_sign_in_path_for(user), 303)
      else
        render_page("new", status: 422)
      end
    end

    def edit
      render_page("edit")
    end

    def update
      user = current_user.not_nil!
      values = {} of String => ::ActiveRecord::Value
      {"email", "password", "password_confirmation", "current_password"}.each do |key|
        if (v = nested_param("user", key))
          values[key] = v
        end
      end
      @resource = user
      if __devise_mapping.update_with_password.call(user, values)
        # sign_in bypasses sign_out — refresh the session key (the salt
        # changes with a new password)
        devise_sign_in(user)
        flash["notice"] = Devise.t!("#{__devise_mapping.scope}.updated", scope: "devise.registrations")
        redirect_to(after_sign_in_path_for(user), 303)
      else
        render_page("edit", status: 422)
      end
    end

    def destroy
      user = current_user.not_nil!
      __devise_mapping.destroy_record.call(user)
      devise_sign_out
      flash["notice"] = Devise.t!("#{__devise_mapping.scope}.destroyed", scope: "devise.registrations")
      redirect_to(after_sign_in_path_for(nil), 303)
    end

    def cancel
      redirect_to(__devise_new_session_path, 303)
    end
  end

  class PasswordsController < DeviseController
    before_action :require_no_authentication, only: [:new, :create, :edit, :update]

    def new
      render_page("new")
    end

    def create
      mapping = __devise_mapping
      if (proc = mapping.send_reset_password_instructions)
        values = {} of String => ::ActiveRecord::Value
        values["email"] = nested_param("user", "email").to_s
        proc.call(values)
      end
      flash["notice"] = Devise.t!("#{__devise_mapping.scope}.send_instructions", scope: "devise.passwords")
      redirect_to(__devise_new_session_path, 303)
    end

    def edit
      render_page("edit")
    end

    def update
      mapping = __devise_mapping
      attrs = {} of String => ::ActiveRecord::Value
      {"reset_password_token", "password", "password_confirmation"}.each do |key|
        if (v = nested_param("user", key)) || (v = params[key]?.try(&.to_s))
          attrs[key] = v
        end
      end
      user = mapping.reset_password_by_token.try(&.call(attrs))
      @resource = user
      if user && user.persisted? && user.errors.empty?
        devise_sign_in(user)
        flash["notice"] = Devise.t!("#{__devise_mapping.scope}.updated", scope: "devise.passwords")
        redirect_to(after_sign_in_path_for(user), 303)
      else
        flash.now("alert", user.try(&.errors.full_messages.join(", ")) ||
                           "Reset password token is invalid")
        render_page("edit", status: 422)
      end
    end
  end

  class ConfirmationsController < DeviseController
    before_action :require_no_authentication, only: [:new, :create]

    def new
      render_page("new")
    end

    def create
      mapping = __devise_mapping
      if (proc = mapping.send_confirmation_instructions)
        proc.call(nested_param("user", "email").to_s)
      end
      flash["notice"] = Devise.t!("#{__devise_mapping.scope}.send_instructions", scope: "devise.confirmations")
      redirect_to(__devise_new_session_path, 303)
    end

    def show
      mapping = __devise_mapping
      token = params["confirmation_token"]?.try(&.to_s).to_s
      user = mapping.confirm_by_token.try(&.call(token))
      if user && user.errors.empty? && mapping.attrs.call(user)["confirmed_at"]?
        flash["notice"] = Devise.t!("#{__devise_mapping.scope}.confirmed", scope: "devise.confirmations")
        redirect_to(__devise_new_session_path, 302)
      else
        flash["alert"] = user.try(&.errors.full_messages.join(", ")) ||
                         "Confirmation token is invalid"
        redirect_to("#{__devise_mapping.path_prefix}/confirmation/new", 302)
      end
    end
  end

  class UnlocksController < DeviseController
    before_action :require_no_authentication, only: [:new, :create]

    def new
      render_page("new")
    end

    def create
      mapping = __devise_mapping
      if (proc = mapping.send_unlock_instructions)
        proc.call(nested_param("user", "email").to_s)
      end
      flash["notice"] = Devise.t!("#{__devise_mapping.scope}.send_instructions", scope: "devise.unlocks")
      redirect_to(__devise_new_session_path, 303)
    end

    def show
      mapping = __devise_mapping
      token = params["unlock_token"]?.try(&.to_s).to_s
      user = mapping.unlock_by_token.try(&.call(token))
      if user
        flash["notice"] = Devise.t!("#{__devise_mapping.scope}.unlocked", scope: "devise.unlocks")
        redirect_to(__devise_new_session_path, 302)
      else
        flash["alert"] = "Unlock token is invalid"
        redirect_to("#{__devise_mapping.path_prefix}/unlock/new", 302)
      end
    end
  end

  # OmniAuth callbacks: request-phase (passthru) и callback-phase.
  # Методы-экшены per-provider генерируются end-of-program кодгеном в
  # http/omniauth_actions.cr (список провайдеров известен только после
  # парсинга моделей).
  class OmniauthCallbacksController < DeviseController
    # Request phase: без OmniAuth- middleware запрос доходит до роутера.
    # Провайдер сконфигурирован → редирект на authorize_url; иначе 404
    # (поведение passthru гема для не-сконфигурированных стратегий).
    def passthru
      provider = params["provider"]?.try(&.to_s).to_s
      client = Devise::OmniAuth.provider_client(provider)
      if client
        redirect_uri = "#{__base_url}#{__devise_mapping.path_prefix}/auth/#{provider}/callback"
        redirect_to(client.authorize_url(redirect_uri), 302)
      else
        head(404)
      end
    end

    # Callback phase (вызывается сгенерированными методами-провайдерами).
    def omniauth_callback(provider : String) : Nil
      mapping = __devise_mapping
      client = Devise::OmniAuth.provider_client(provider)
      unless client
        head(404)
        return
      end
      code = params["code"]?.try(&.to_s).to_s
      redirect_uri = "#{__base_url}#{mapping.path_prefix}/auth/#{provider}/callback"
      auth = client.authenticate(code, redirect_uri)
      user = mapping.omniauth_callback.try(&.call(auth))
      if user
        devise_sign_in(user)
        flash["notice"] = Devise.t!("#{__devise_mapping.scope}.signed_in", scope: "devise.sessions")
        redirect_to(after_sign_in_path_for(user), 303)
      else
        flash["alert"] = "Could not authenticate you from #{provider.titlecase}."
        redirect_to(__devise_new_session_path, 302)
      end
    end

    private def __base_url : String
      scheme = request.headers["X-Forwarded-Proto"]? || "http"
      host = request.headers["Host"]? || "localhost"
      "#{scheme}://#{host}"
    end
  end
end
