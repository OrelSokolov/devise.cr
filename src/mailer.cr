# Devise::Mailer — port of app/mailers/devise/mailer.rb (devise 4.9.4) on
# top of action_mailer_cr. Actions mirror the gem 1:1
# (confirmation_instructions / reset_password_instructions /
# unlock_instructions / email_changed / password_change); subjects are the
# en.yml defaults ("Reset password instructions", ...).

module Devise
  class Mailer < ActionMailer::Base
    # from: mailer_sender (the gem resolves it per mapping; single-scope
    # port — Devise.mailer_sender).
    def __default_from : String?
      Devise.mailer_sender
    end

    def confirmation_instructions(record, token, opts = {} of String => ::ActiveRecord::Value)
      devise_mail(record, subject_for(:confirmation_instructions), opts)
    end

    def reset_password_instructions(record, token, opts = {} of String => ::ActiveRecord::Value)
      devise_mail(record, subject_for(:reset_password_instructions), opts)
    end

    def unlock_instructions(record, token, opts = {} of String => ::ActiveRecord::Value)
      devise_mail(record, subject_for(:unlock_instructions), opts)
    end

    def email_changed(record, opts = {} of String => ::ActiveRecord::Value)
      devise_mail(record, subject_for(:email_changed), opts)
    end

    def password_change(record, opts = {} of String => ::ActiveRecord::Value)
      devise_mail(record, subject_for(:password_change), opts)
    end

    # subject_for гема: I18n.t(:"<scope>_subject", scope: [:devise,
    # :mailer, key], default: [:subject, key.humanize]) — в порту
    # Devise.t с той же цепочкой промах → "subject".
    private def subject_for(key : Symbol) : String?
      Devise.t!("#{Devise.default_scope}_subject", scope: "devise.mailer.#{key}")
    end

    # Тело действия инстанцируется дважды: прямым вызовом из
    # deliver_devise_notification (record — AR-модель, opts — Hash) и
    # action_mailer's __deliver codegen'ом (deliver_later; все аргументы —
    # serialized ActiveJob::ArgValue). У ArgValue нет #[]?(String)
    # (Array-ветка), а attributes генерится на конкретных моделях, не на
    # Base+ — поэтому доступ идёт через as?(Hash) и оверлоад по record
    # (сериализованный путь email не знает: AR-записи в ArgValue не
    # входят, GlobalID-сериализации нет).
    private def devise_mail(record, subject, opts)
      to = __opts_get(opts, "to") || __record_email(record)
      mail(to: to, subject: subject, body: __opts_get(opts, "body") || "")
    end

    private def __opts_get(opts, key : String) : String?
      opts.as?(Hash).try { |h| h[key]?.try(&.to_s) }
    end

    private def __record_email(record : ::ActiveJob::ArgValue) : String?
      nil
    end

    private def __record_email(record) : String?
      record.attributes["email"]?.try(&.to_s)
    end

    # Model-side dispatch: send_devise_notification(:reset_password_instructions, raw, opts?)
    # (instance-level: the delivery twin's ActiveJob arg serialization does
    # not apply to immediate delivery)
    def self.deliver_devise_notification(record : ActiveRecord::Base,
                                         notification : Symbol,
                                         args : Array(String | Hash(String, ::ActiveRecord::Value))) : Nil
      opts = args[1]? || {} of String => ::ActiveRecord::Value
      mailer = new
      msg = case notification
            when :confirmation_instructions
              mailer.confirmation_instructions(record, args[0].to_s, opts)
            when :reset_password_instructions
              mailer.reset_password_instructions(record, args[0].to_s, opts)
            when :unlock_instructions
              mailer.unlock_instructions(record, args[0].to_s, opts)
            when :email_changed
              mailer.email_changed(record, opts)
            when :password_change
              mailer.password_change(record, opts)
            else
              raise ArgumentError.new("unknown devise notification: #{notification}")
            end
      # NB: Crystal не ищет константы в superclass-скопах (в отличие от
      # Ruby), поэтому Base нужно полное имя ActionMailer::Base.
      ActionMailer::Base.deliver(msg)
    end
  end
end
