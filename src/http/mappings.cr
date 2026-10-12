# Devise scope mappings (аналог Devise.mappings): реестр моделей с
# devise-модулями. Заполняется макросом `devise` на компиляции (в
# models.cr), лукап — Devise.mapping(scope) через end-of-program кодген
# (паттерн ActionCable.lookup_channel). Ключ — underscore имени класса
# ("user"); devise_for(:users) ищет по singularize.
#
# Class-level операции (find/where/new/сериализация remember-cookie)
# пробрасываются типизированными Proc.new-проками через локальные
# переменные: статический тип ActiveRecord::Base.class не знает
# метаметодов конкретных моделей (генерируются макросом `devise`), а
# прок-литералы в позиции аргумента вызова Crystal-парсер не принимает.

module Devise
  # Runtime lookup result: модель + скоп + модули + диспетчеры.
  # (Compile-time реестр MAPPINGS живёт в models.cr.)
  struct Mapping
    getter scope : String # "user"
    getter modules : Array(Symbol)
    getter providers : Array(Symbol)
    getter find : Proc(Int64, ::ActiveRecord::Base?)
    getter find_by_email : Proc(String, ::ActiveRecord::Base?)
    getter find_by_token : Proc(String, String, ::ActiveRecord::Base?)
    getter build : Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base)
    getter attrs : Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value))
    getter valid_password : Proc(::ActiveRecord::Base, String, Bool)
    getter update_with_password : Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value), Bool)
    getter save_unvalidated : Proc(::ActiveRecord::Base, Bool)
    getter save_validated : Proc(::ActiveRecord::Base, Bool)
    getter assign : Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value), Nil)
    getter destroy_record : Proc(::ActiveRecord::Base, Nil)
    getter with_reset_password_token : Proc(String, ::ActiveRecord::Base?)?
    getter reset_password_by_token : Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base?)?
    getter send_reset_password_instructions : Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base?)?
    getter send_confirmation_instructions : Proc(String, ::ActiveRecord::Base?)?
    getter confirm_by_token : Proc(String, ::ActiveRecord::Base?)?
    getter send_unlock_instructions : Proc(String, ::ActiveRecord::Base?)?
    getter unlock_by_token : Proc(String, ::ActiveRecord::Base?)?
    getter omniauth_callback : Proc(Devise::OmniAuth::AuthHash, ::ActiveRecord::Base?)?
    getter serialize_from_cookie : Proc(Array(Int64), String, String, ::ActiveRecord::Base?)?

    def initialize(@scope, @modules, @providers, @find, @find_by_email,
                   @find_by_token, @build, @attrs, @valid_password,
                   @update_with_password, @save_unvalidated, @save_validated,
                   @assign, @destroy_record,
                   @with_reset_password_token,
                   @reset_password_by_token, @send_reset_password_instructions,
                   @send_confirmation_instructions, @confirm_by_token,
                   @send_unlock_instructions, @unlock_by_token,
                   @omniauth_callback, @serialize_from_cookie)
    end

    def path_prefix : String
      "/#{@scope.pluralize}"
    end
  end

  # devise_for(:users) → Mapping(user). nil когда модель не найдена.
  def self.mapping(resource : String | Symbol) : Mapping?
    mapping_for(resource.to_s.singularize)
  end

  # Генерируется макросом finished ниже (все классы известны к концу
  # программы).
  def self.mapping_for(scope : String) : Mapping?
    nil
  end
end

macro finished
  def Devise.mapping_for(scope : String) : Devise::Mapping?
    case scope
    {% for m in Devise::MAPPINGS %}
    when {{ m[:key] }}
      find = Proc(Int64, ::ActiveRecord::Base?).new { |id| {{ m[:type].id }}.find?(id) }
      find_by_email = Proc(String, ::ActiveRecord::Base?).new { |email| {{ m[:type].id }}.where("LOWER(email) = LOWER(?)", email).first? }
      find_by_token = Proc(String, String, ::ActiveRecord::Base?).new { |column, digest| {{ m[:type].id }}.where(column + " = ?", digest).first? }
      build = Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base).new { |values| {{ m[:type].id }}.new(values) }
      attrs = Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value)).new { |u| u.as({{ m[:type].id }}).attributes }
      valid_password = Proc(::ActiveRecord::Base, String, Bool).new { |u, pw| u.as({{ m[:type].id }}).valid_password?(pw) }
      update_with_password = Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value), Bool).new { |u, values| u.as({{ m[:type].id }}).update_with_password(values) }
      save_unvalidated = Proc(::ActiveRecord::Base, Bool).new { |u| u.as({{ m[:type].id }}).save(validate: false) }
      save_validated = Proc(::ActiveRecord::Base, Bool).new { |u| u.as({{ m[:type].id }}).save }
      assign = Proc(::ActiveRecord::Base, Hash(String, ::ActiveRecord::Value), Nil).new { |u, values| u.as({{ m[:type].id }}).assign_attributes(values) }
      destroy_record = Proc(::ActiveRecord::Base, Nil).new { |u| u.as({{ m[:type].id }}).destroy; nil }
      {% if m[:modules].includes?(:recoverable) %}
        with_reset = Proc(String, ::ActiveRecord::Base?).new { |token| {{ m[:type].id }}.with_reset_password_token(token) }
        reset_by_token = Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base?).new { |attrs| u = {{ m[:type].id }}.reset_password_by_token(attrs); u }
        send_reset = Proc(Hash(String, ::ActiveRecord::Value), ::ActiveRecord::Base?).new { |attrs| u = {{ m[:type].id }}.send_reset_password_instructions(attrs); u }
      {% else %}
        with_reset = nil
        reset_by_token = nil
        send_reset = nil
      {% end %}
      {% if m[:modules].includes?(:confirmable) %}
        send_confirmation = Proc(String, ::ActiveRecord::Base?).new { |email| u = {{ m[:type].id }}.where("LOWER(email) = LOWER(?)", email).first?; u.try(&.resend_confirmation_instructions); u }
        # confirmation_token хранится raw (модельный порт, models_p1);
        # unlock_token — digest
        confirm_by = Proc(String, ::ActiveRecord::Base?).new { |token|
          u = {{ m[:type].id }}.where("confirmation_token = ?", token).first?
          if u
            u.confirm
          end
          u
        }
      {% else %}
        send_confirmation = nil
        confirm_by = nil
      {% end %}
      {% if m[:modules].includes?(:lockable) %}
        send_unlock = Proc(String, ::ActiveRecord::Base?).new { |email| u = {{ m[:type].id }}.where("LOWER(email) = LOWER(?)", email).first?; u.try(&.send_unlock_instructions); u }
        unlock_by = Proc(String, ::ActiveRecord::Base?).new { |token|
          u = {{ m[:type].id }}.where("unlock_token = ?", Devise.token_generator.digest("unlock_token", token).to_s).first?
          if u
            u.unlock_access!
          end
          u
        }
      {% else %}
        send_unlock = nil
        unlock_by = nil
      {% end %}
      {% if m[:modules].includes?(:omniauthable) %}
        omniauth_cb = Proc(Devise::OmniAuth::AuthHash, ::ActiveRecord::Base?).new { |auth| {{ m[:type].id }}.from_omniauth(auth) }
      {% else %}
        omniauth_cb = nil
      {% end %}
      {% if m[:modules].includes?(:rememberable) %}
        remember_cb = Proc(Array(Int64), String, String, ::ActiveRecord::Base?).new { |key, token, gen| {{ m[:type].id }}.serialize_from_cookie(key, token, gen) }
      {% else %}
        remember_cb = nil
      {% end %}
      Devise::Mapping.new({{ m[:key] }}, [{{ m[:modules].splat }}] of Symbol,
        [{{ m[:providers].splat }}] of Symbol, find, find_by_email,
        find_by_token, build, attrs, valid_password, update_with_password,
        save_unvalidated, save_validated, assign, destroy_record, with_reset, reset_by_token, send_reset,
        send_confirmation, confirm_by, send_unlock, unlock_by,
        omniauth_cb, remember_cb)
    {% end %}
    else
      nil
    end
  end
end
