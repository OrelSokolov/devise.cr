# P1 devise modules: recoverable / confirmable / trackable / lockable /
# timeoutable — emitted from the `devise` macro in models.cr via
# `devise_p1(modules)`, mirroring lib/devise/models/*.rb of devise 4.9.4.
#
# Deviations from the gem (documented):
#   * confirmation_token is stored RAW (exactly like the gem 4.9.4);
#     reset/unlock tokens are stored as HMAC-SHA256 hex digests.
#   * update_tracked_fields takes a Devise::RequestInfo (remote_ip) —
#     no Rack request type exists here.
#   * active_for_authentication?/inactive_message/valid_for_authentication?
#     are generated as ONE combined method per model (the gem chains
#     module `super`; here the module set is known at compile time).

module Devise
  # Global defaults mirroring lib/devise.rb (devise 4.9.4).
  class_property mailer_sender : String? = nil
  class_property paranoid = false
  class_property reset_password_within : Time::Span = 6.hours
  class_property allow_unconfirmed_access_for : Time::Span? = Time::Span.zero
  class_property confirm_within : Time::Span? = nil
  class_property reconfirmable = true
  class_property maximum_attempts : Int32 = 20
  class_property lock_strategy : Symbol = :failed_attempts
  class_property unlock_strategy : Symbol = :both
  class_property unlock_in : Time::Span = 1.hour
  class_property timeout_in : Time::Span? = 30.minutes
  class_property last_attempt_warning = true

  # Trackable request stand-in (Rack request has no port type here).
  struct RequestInfo
    getter remote_ip : String

    def initialize(@remote_ip)
    end
  end
end

class ActiveRecord::Base
  macro devise_p1(modules)
    {% has_recoverable = modules.includes?(:recoverable) %}
    {% has_confirmable = modules.includes?(:confirmable) %}
    {% has_trackable = modules.includes?(:trackable) %}
    {% has_lockable = modules.includes?(:lockable) %}
    {% has_timeoutable = modules.includes?(:timeoutable) %}

    # --- per-class config overrides (Devise::Models.config) ---------------
    {% if has_recoverable %}
      @@devise_reset_password_within : Time::Span? = nil

      def self.reset_password_within : Time::Span
        @@devise_reset_password_within || Devise.reset_password_within
      end

      def self.reset_password_within=(value : Time::Span?)
        @@devise_reset_password_within = value
      end
    {% end %}

    {% if has_confirmable %}
      @@devise_allow_unconfirmed_access_for : Time::Span? = nil
      @@devise_allow_unconfirmed_access_for_set = false
      @@devise_confirm_within : Time::Span? = nil
      @@devise_confirm_within_set = false
      @@devise_reconfirmable : Bool? = nil

      # `*_set` marks an explicit class-level override — assigning nil must
      # stick (the gem's class attrs default FROM the global config, and
      # `self.confirm_within = nil` disables the window).
      def self.allow_unconfirmed_access_for : Time::Span?
        @@devise_allow_unconfirmed_access_for_set ? @@devise_allow_unconfirmed_access_for : Devise.allow_unconfirmed_access_for
      end

      def self.allow_unconfirmed_access_for=(value : Time::Span?)
        @@devise_allow_unconfirmed_access_for = value
        @@devise_allow_unconfirmed_access_for_set = true
      end

      def self.confirm_within : Time::Span?
        @@devise_confirm_within_set ? @@devise_confirm_within : Devise.confirm_within
      end

      def self.confirm_within=(value : Time::Span?)
        @@devise_confirm_within = value
        @@devise_confirm_within_set = true
      end

      def self.reconfirmable? : Bool
        @@devise_reconfirmable.nil? ? Devise.reconfirmable : @@devise_reconfirmable.not_nil!
      end

      def self.reconfirmable=(value : Bool)
        @@devise_reconfirmable = value
      end
    {% end %}

    {% if has_lockable %}
      @@devise_maximum_attempts : Int32? = nil
      @@devise_lock_strategy : Symbol? = nil
      @@devise_unlock_strategy : Symbol? = nil
      @@devise_unlock_in : Time::Span? = nil

      def self.maximum_attempts : Int32
        @@devise_maximum_attempts || Devise.maximum_attempts
      end

      def self.maximum_attempts=(value : Int32)
        @@devise_maximum_attempts = value
      end

      def self.lock_strategy : Symbol
        @@devise_lock_strategy || Devise.lock_strategy
      end

      def self.lock_strategy=(value : Symbol)
        @@devise_lock_strategy = value
      end

      def self.unlock_strategy : Symbol
        @@devise_unlock_strategy || Devise.unlock_strategy
      end

      def self.unlock_strategy=(value : Symbol)
        @@devise_unlock_strategy = value
      end

      def self.unlock_in : Time::Span
        @@devise_unlock_in || Devise.unlock_in
      end

      def self.unlock_in=(value : Time::Span)
        @@devise_unlock_in = value
      end

      BOTH_UNLOCK_STRATEGIES = [:time, :email]

      def self.unlock_strategy_enabled?(strategy : Symbol) : Bool
        unlock_strategy == strategy ||
          (unlock_strategy == :both && BOTH_UNLOCK_STRATEGIES.includes?(strategy))
      end

      def self.lock_strategy_enabled?(strategy : Symbol) : Bool
        lock_strategy == strategy
      end
    {% end %}

    {% if has_timeoutable %}
      @@devise_timeout_in : Time::Span? = nil
      @@devise_timeout_in_set = false

      def self.timeout_in : Time::Span?
        @@devise_timeout_in_set ? @@devise_timeout_in : Devise.timeout_in
      end

      def self.timeout_in=(value : Time::Span?)
        @@devise_timeout_in = value
        @@devise_timeout_in_set = true
      end
    {% end %}

    # --- shared notification dispatch (authenticatable) --------------------
    def send_devise_notification(notification : Symbol, *args) : Nil
      Devise::Mailer.deliver_devise_notification(self, notification, args.to_a)
    end

    {% if has_confirmable || has_lockable %}
      def active_for_authentication? : Bool
        result = true
        {% if has_confirmable %}
          result = result && (!confirmation_required? || confirmed? || confirmation_period_valid?)
        {% end %}
        {% if has_lockable %}
          result = result && !access_locked?
        {% end %}
        result
      end

      def inactive_message : Symbol
        {% if has_lockable %}
          return :locked if access_locked?
        {% end %}
        {% if has_confirmable %}
          return :unconfirmed unless confirmed?
        {% end %}
        :inactive
      end
    {% end %}

    {% if has_lockable %}
      def unauthenticated_message : Symbol
        if Devise.paranoid
          :invalid
        elsif access_locked? || (self.class.lock_strategy_enabled?(:failed_attempts) && attempts_exceeded?)
          :locked
        elsif self.class.lock_strategy_enabled?(:failed_attempts) &&
              last_attempt? && Devise.last_attempt_warning
          :last_attempt
        else
          :invalid
        end
      end

      def valid_for_authentication? : Bool
        authed = yield
        unless persisted? && self.class.lock_strategy_enabled?(:failed_attempts)
          return authed
        end
        unlock_access! if lock_expired?
        if authed && !access_locked?
          true
        else
          increment_failed_attempts
          if attempts_exceeded?
            lock_access! unless access_locked?
          else
            save(validate: false)
          end
          false
        end
      end
    {% else %}
      def valid_for_authentication? : Bool
        yield
      end
    {% end %}

    # --- find_or_initialize_with_errors (authenticatable) -------------------
    # (keys are the devise *_keys configs — [:email] by default; the first
    # key present in attributes wins, which for the default single key set
    # is exactly the gem's AND lookup.)
    def self.find_or_initialize_with_errors(keys : Array(String),
                                            attributes : Hash(String, ::ActiveRecord::Value),
                                            message : Symbol) : self
      record = nil
      keys.each do |k|
        value = attributes[k]?
        next if value.nil?
        record = where("#{k} = ?", value).first?
        break
      end
      record ||= new
      unless record.persisted?
        record.errors.add(keys.first, message)
      end
      record
    end

    # --- recoverable ---------------------------------------------------------
    {% if has_recoverable %}
      before_save :__devise_clear_reset_password_token

      def __devise_clear_reset_password_token : Nil
        return if new_record? # before_update
        if will_save_change_to_encrypted_password? || will_save_change_to_email?
          self.reset_password_token = nil
          self.reset_password_sent_at = nil
        end
      end

      def reset_password(new_password : String?, new_password_confirmation : String?) : Bool
        if new_password && !new_password.empty?
          self.password = new_password
          self.password_confirmation = new_password_confirmation
          save
        else
          errors.add("password", :blank)
          false
        end
      end

      def send_reset_password_instructions : String
        token = set_reset_password_token
        send_devise_notification(:reset_password_instructions, token)
        token
      end

      def set_reset_password_token : String
        raw, enc = Devise.token_generator.generate(self.class, "reset_password_token")
        self.reset_password_token = enc
        self.reset_password_sent_at = Time.utc
        save(validate: false)
        raw
      end

      def reset_password_period_valid? : Bool
        sent = reset_password_sent_at
        !sent.nil? && sent >= Time.utc - self.class.reset_password_within
      end

      def self.with_reset_password_token(token : String) : self?
        digest = Devise.token_generator.digest("reset_password_token", token).as(String)
        where("reset_password_token = ?", digest).first?
      end

      def self.send_reset_password_instructions(attributes : Hash(String, ::ActiveRecord::Value)) : self
        recoverable = find_or_initialize_with_errors(["email"], attributes, :not_found)
        recoverable.send_reset_password_instructions if recoverable.persisted?
        recoverable
      end

      def self.reset_password_by_token(attributes : Hash(String, ::ActiveRecord::Value)) : self
        original_token = attributes["reset_password_token"]?.try(&.to_s).to_s
        digest = Devise.token_generator.digest("reset_password_token", original_token)

        recoverable = where("reset_password_token = ?", digest).first? || new
        unless recoverable.persisted?
          recoverable.errors.add("reset_password_token", :invalid)
        end

        if recoverable.persisted?
          if recoverable.reset_password_period_valid?
            recoverable.reset_password(attributes["password"]?.try(&.to_s),
                                       attributes["password_confirmation"]?.try(&.to_s))
          else
            recoverable.errors.add("reset_password_token", :expired)
          end
        end

        recoverable.reset_password_token = original_token unless recoverable.reset_password_token.to_s.empty?
        recoverable
      end
    {% end %}

    # --- confirmable ---------------------------------------------------------
    {% if has_confirmable %}
      @devise_raw_confirmation_token : String? = nil
      @devise_reconfirmation_required = false
      @devise_skip_confirmation_notification = false
      @devise_bypass_confirmation_postpone = false
      @devise_skip_reconfirmation_in_callback = false

      before_save :__devise_generate_confirmation_token
      after_create :__devise_skip_reconfirmation_in_callback
      after_commit(:create) { __devise_send_on_create_confirmation_instructions }
      before_save :__devise_postpone_email_change
      after_commit(:update) { __devise_send_reconfirmation_instructions }

      # before_create hook (the gem: `if: :confirmation_required?`).
      def __devise_generate_confirmation_token : Nil
        return unless new_record?
        return unless confirmation_required?
        __devise_generate_token_columns
      end

      # The raw column mutation shared by the create hook and postpone.
      def __devise_generate_token_columns : Nil
        if (tok = confirmation_token) && !confirmation_period_expired?
          @devise_raw_confirmation_token = tok
        else
          @devise_raw_confirmation_token = Devise.friendly_token
          self.confirmation_token = @devise_raw_confirmation_token
          self.confirmation_sent_at = Time.utc
        end
      end

      def __devise_skip_reconfirmation_in_callback : Nil
        return unless send_confirmation_notification?
        @devise_skip_reconfirmation_in_callback = true
      end

      def __devise_send_on_create_confirmation_instructions : Nil
        return unless send_confirmation_notification?
        send_confirmation_instructions
      end

      def __devise_postpone_email_change : Nil
        return if new_record? # before_update
        return unless postpone_email_change?
        @devise_reconfirmation_required = true
        self.unconfirmed_email = email
        self.email = email_was.as?(String)
        self.confirmation_token = nil
        __devise_generate_token_columns
      end

      def __devise_send_reconfirmation_instructions : Nil
        return unless reconfirmation_required?
        @devise_reconfirmation_required = false
        send_confirmation_instructions unless @devise_skip_confirmation_notification
      end

      def postpone_email_change? : Bool
        postpone = self.class.reconfirmable? &&
                   will_save_change_to_email? &&
                   !@devise_bypass_confirmation_postpone &&
                   !email.to_s.empty? &&
                   (!@devise_skip_reconfirmation_in_callback || !email_was.as?(String).nil?)
        @devise_bypass_confirmation_postpone = false
        postpone
      end

      def reconfirmation_required? : Bool
        self.class.reconfirmable? && @devise_reconfirmation_required &&
          (!email.to_s.empty? || !unconfirmed_email.to_s.empty?)
      end

      def send_confirmation_notification? : Bool
        confirmation_required? && !@devise_skip_confirmation_notification && !email.to_s.empty?
      end

      def confirmation_required? : Bool
        !confirmed?
      end

      def confirmed? : Bool
        !confirmed_at.nil?
      end

      def pending_reconfirmation? : Bool
        self.class.reconfirmable? && !unconfirmed_email.to_s.empty?
      end

      def confirmation_period_valid? : Bool
        window = self.class.allow_unconfirmed_access_for
        return true if window.nil?
        return false if window.total_seconds == 0
        sent = confirmation_sent_at
        !sent.nil? && sent >= Time.utc - window
      end

      def confirmation_period_expired? : Bool
        window = self.class.confirm_within
        sent = confirmation_sent_at
        !window.nil? && !sent.nil? && Time.utc > sent + window
      end

      # Confirm the user; false + :already_confirmed if nothing pending.
      def confirm(ensure_valid : Bool = false) : Bool
        unless !confirmed? || pending_reconfirmation?
          errors.add("email", :already_confirmed)
          return false
        end
        if confirmation_period_expired?
          errors.add("email", :confirmation_period_expired)
          return false
        end

        self.confirmed_at = Time.utc
        saved = if pending_reconfirmation?
          skip_reconfirmation!
          self.email = unconfirmed_email
          self.unconfirmed_email = nil
          save
        else
          save(validate: ensure_valid)
        end
        saved
      end

      def send_confirmation_instructions : Nil
        generate_confirmation_token! unless @devise_raw_confirmation_token
        opts = {} of String => ::ActiveRecord::Value
        opts["to"] = unconfirmed_email.not_nil! if pending_reconfirmation?
        send_devise_notification(:confirmation_instructions, @devise_raw_confirmation_token.not_nil!, opts)
      end

      def generate_confirmation_token! : Nil
        __devise_generate_token_columns
        save(validate: false)
      end

      def resend_confirmation_instructions : Nil
        unless !confirmed? || pending_reconfirmation?
          errors.add("email", :already_confirmed)
        else
          send_confirmation_instructions
        end
      end

      def skip_confirmation! : Nil
        self.confirmed_at = Time.utc
      end

      def skip_confirmation_notification! : Nil
        @devise_skip_confirmation_notification = true
      end

      def skip_reconfirmation! : Nil
        @devise_bypass_confirmation_postpone = true
      end

      def self.confirm_by_token(confirmation_token : String) : self
        if confirmation_token.empty?
          confirmable = new
          confirmable.errors.add("confirmation_token", :blank)
          return confirmable
        end

        # The gem stores the RAW confirmation token (legacy) and falls back
        # to the digest for tokens issued by older/other clients.
        confirmable = where("confirmation_token = ?", confirmation_token).first?
        unless confirmable
          if (digest = Devise.token_generator.digest("confirmation_token", confirmation_token))
            confirmable = where("confirmation_token = ?", digest).first?
          end
        end
        unless confirmable
          confirmable = new
          confirmable.errors.add("confirmation_token", :invalid)
          return confirmable
        end

        confirmable.confirm if confirmable.persisted?
        confirmable
      end

      def self.send_confirmation_instructions(attributes : Hash(String, ::ActiveRecord::Value)) : self
        confirmable = find_or_initialize_with_errors(["email"], attributes, :not_found)
        if confirmable.persisted?
          confirmable.resend_confirmation_instructions
        end
        confirmable
      end
    {% end %}

    # --- trackable -----------------------------------------------------------
    {% if has_trackable %}
      def update_tracked_fields(request : Devise::RequestInfo) : Nil
        old_current = current_sign_in_at
        new_current = Time.utc
        self.last_sign_in_at = old_current || new_current
        self.current_sign_in_at = new_current

        old_ip = current_sign_in_ip
        new_ip = request.remote_ip
        self.last_sign_in_ip = old_ip || new_ip
        self.current_sign_in_ip = new_ip

        self.sign_in_count = sign_in_count.nil? ? 1_i64 : sign_in_count.not_nil! + 1_i64
      end

      def update_tracked_fields!(request : Devise::RequestInfo) : Nil
        return if new_record?
        update_tracked_fields(request)
        save(validate: false)
      end
    {% end %}

    # --- lockable ------------------------------------------------------------
    {% if has_lockable %}
      def lock_access!(send_instructions : Bool = true) : Nil
        self.locked_at = Time.utc
        if self.class.unlock_strategy_enabled?(:email) && send_instructions
          send_unlock_instructions
        else
          save(validate: false)
        end
      end

      def unlock_access! : Nil
        self.locked_at = nil
        self.failed_attempts = 0
        self.unlock_token = nil
        save(validate: false)
      end

      def reset_failed_attempts! : Nil
        if !persisted?
          return
        end
        unless (failed_attempts || 0) == 0
          self.failed_attempts = 0
          save(validate: false)
        end
      end

      def access_locked? : Bool
        !locked_at.nil? && !lock_expired?
      end

      def send_unlock_instructions : String
        raw, enc = Devise.token_generator.generate(self.class, "unlock_token")
        self.unlock_token = enc
        save(validate: false)
        send_devise_notification(:unlock_instructions, raw)
        raw
      end

      def resend_unlock_instructions : Nil
        if access_locked?
          send_unlock_instructions
        else
          errors.add("email", :not_locked)
        end
      end

      def attempts_exceeded? : Bool
        (failed_attempts || 0) >= self.class.maximum_attempts
      end

      def last_attempt? : Bool
        (failed_attempts || 0) == self.class.maximum_attempts - 1
      end

      def lock_expired? : Bool
        return false unless self.class.unlock_strategy_enabled?(:time)
        locked = locked_at
        !locked.nil? && locked < Time.utc - self.class.unlock_in
      end

      def increment_failed_attempts : Nil
        self.failed_attempts = failed_attempts.nil? ? 1_i64 : failed_attempts.not_nil! + 1_i64
      end

      def self.unlock_access_by_token(unlock_token : String) : self
        original_token = unlock_token
        digest = Devise.token_generator.digest("unlock_token", unlock_token).as(String)

        lockable = where("unlock_token = ?", digest).first? || new
        unless lockable.persisted?
          lockable.errors.add("unlock_token", :invalid)
          return lockable
        end

        lockable.unlock_access! if lockable.persisted?
        lockable.unlock_token = original_token
        lockable
      end

      def self.send_unlock_instructions(attributes : Hash(String, ::ActiveRecord::Value)) : self
        lockable = find_or_initialize_with_errors(["email"], attributes, :not_found)
        lockable.resend_unlock_instructions if lockable.persisted?
        lockable
      end
    {% end %}

    # --- timeoutable -----------------------------------------------------------
    {% if has_timeoutable %}
      def timedout?(last_access : Time?) : Bool?
        window = self.class.timeout_in
        return false if window.nil?
        return nil if last_access.nil? # Ruby: `last_access && ...` → nil
        !window.nil? && !last_access.nil? && last_access <= Time.utc - window
      end

      def timeout_in : Time::Span?
        self.class.timeout_in
      end
    {% end %}
  end
end
