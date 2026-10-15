# Devise model DSL — the `devise` macro wires database_authenticatable,
# validatable, rememberable and registerable into an AR model (the gem
# includes the module concerns; here one macro generates the same
# surface). Validations are emitted as validation__devise_* methods that
# the AR validation runner picks up by prefix.

module Devise
  # Defaults mirroring lib/devise.rb (devise 4.9.4).
  class_property pepper : String? = nil
  class_property stretches : Int32 = 12
  class_property password_length : Range(Int32, Int32) = 6..128
  class_property remember_for : Time::Span = 14.days
  class_property email_regexp = /\A[^@\s]+@[^@\s]+\z/

  # HTTP-layer registries (see src/http/mappings.cr): filled by the
  # `devise` macro below, looked up by end-of-program codegen.
  MAPPINGS = [] of Nil
end

class ActiveRecord::Base
  macro devise(*modules, **options)
    {% has_auth = modules.includes?(:database_authenticatable) %}
    {% has_validatable = modules.includes?(:validatable) %}
    {% has_rememberable = modules.includes?(:rememberable) %}
    {% if options.is_a?(NamedTupleLiteral) && options.keys.map(&.stringify).includes?("omniauth_providers") %}
      {% providers = options[:omniauth_providers] %}
    {% else %}
      {% providers = [] of SymbolLiteral %}
    {% end %}
    {% Devise::MAPPINGS << {type: @type.name.stringify, key: @type.name.split("::").last.underscore, modules: modules, providers: providers} %}

    @@devise_pepper : String? = nil
    @@devise_stretches : Int32? = nil

    def self.pepper : String?
      @@devise_pepper || Devise.pepper
    end

    def self.pepper=(value : String?)
      @@devise_pepper = value
    end

    def self.stretches : Int32
      @@devise_stretches || Devise.stretches
    end

    def self.stretches=(value : Int32)
      @@devise_stretches = value
    end

    def devise_pepper : String?
      self.class.pepper
    end

    def devise_stretches : Int32
      self.class.stretches
    end

    # --- database_authenticatable -------------------------------------
    @devise_password : String? = nil
    @devise_password_confirmation : String? = nil

    def password : String?
      @devise_password
    end

    def password=(new_password : String?)
      @devise_password = new_password
      if new_password && !new_password.empty?
        self.encrypted_password = Devise::Encryptor.digest(devise_pepper, devise_stretches, new_password)
      end
      new_password
    end

    def password_confirmation : String?
      @devise_password_confirmation
    end

    def password_confirmation=(value : String?)
      @devise_password_confirmation = value
    end

    def clean_up_passwords : Nil
      @devise_password = nil
      @devise_password_confirmation = nil
    end

    def valid_password?(password : String) : Bool
      Devise::Encryptor.compare(devise_pepper, encrypted_password.to_s, password)
    end

    def update_with_password(params : Hash(String, ActiveRecord::Value)) : Bool
      values = params.dup
      current_password = values.delete("current_password").try(&.to_s).to_s

      if values["password"]?.try(&.to_s).to_s.empty?
        values.delete("password")
        if values["password_confirmation"]?.try(&.to_s).to_s.empty?
          values.delete("password_confirmation")
        end
      end

      new_password = values.delete("password").try(&.to_s)
      new_confirmation = values.delete("password_confirmation").try(&.to_s)

      result = if valid_password?(current_password)
                 self.password = new_password if new_password && !new_password.empty?
                 self.password_confirmation = new_confirmation
                 update(values)
               else
                 errors.add("current_password", current_password.empty? ? :blank : :invalid)
                 false
               end
      clean_up_passwords
      result
    end

    def update_without_password(params : Hash(String, ActiveRecord::Value)) : Bool
      values = params.dup
      values.delete("password")
      values.delete("password_confirmation")
      result = update(values)
      clean_up_passwords
      result
    end

    # new/create/create! with :password / :password_confirmation keys — the
    # password must land on the record BEFORE save so validations see it.
    # (Also gives the gem idiom `User.new({"email" => ..., "password" => ...})`
    # a working path: the generated keyword initialize has no such overload.)
    def self.new(values : Hash(String, ::ActiveRecord::Value) = {} of String => ::ActiveRecord::Value) : self
      vals = values.dup
      password = vals.delete("password").try(&.to_s)
      confirmation = vals.delete("password_confirmation").try(&.to_s)
      record = new(for_load: false)
      record.assign_attributes(vals)
      record.password = password if password
      record.password_confirmation = confirmation
      record
    end

    def self.create!(values : Hash(String, ::ActiveRecord::Value) = {} of String => ::ActiveRecord::Value) : self
      record = new(values)
      record.save!
      record
    end

    def self.create(values : Hash(String, ::ActiveRecord::Value) = {} of String => ::ActiveRecord::Value) : self
      record = new(values)
      record.save
      record
    end

    # --- validatable ------------------------------------------------------
    def password_required? : Bool
      !persisted? || !@devise_password.nil? || !@devise_password_confirmation.nil?
    end

    {% if has_validatable %}
      def validation__devise_email(context : Symbol) : Nil
        email = attributes["email"]?.try(&.to_s).to_s
        if email.empty?
          errors.add("email", :blank)
          return
        end
        unless email =~ Devise.email_regexp
          errors.add("email", :invalid)
        end
        # uniqueness — case-insensitive match (oracle: upcased duplicate is taken)
        if existing = self.class.where("LOWER(email) = LOWER(?)", email).first?
          unless existing.id == self.id
            errors.add("email", :taken)
          end
        end
      end

      def validation__devise_password(context : Symbol) : Nil
        if password_required?
          pw = @devise_password
          if pw.nil? || pw.empty?
            errors.add("password", :blank)
          else
            length = Devise.password_length
            if pw.size < length.begin
              errors.add("password", :too_short)
            elsif pw.size > length.end
              errors.add("password", :too_long)
            end
          end
          if (conf = @devise_password_confirmation) && conf != @devise_password
            errors.add("password_confirmation", "doesn't match Password", :confirmation)
          end
        end
      end
    {% end %}

    # --- authenticatable / rememberable -----------------------------------
    def authenticatable_salt : String?
      ep = encrypted_password.to_s
      ep.empty? ? nil : ep[0, 29]
    end

    {% if has_rememberable %}
      def remember_me! : Nil
        if remember_created_at.nil?
          self.remember_created_at = Time.utc
          save(validate: false)
        end
      end

      def forget_me! : Nil
        return unless persisted?
        self.remember_created_at = nil
        save(validate: false)
      end

      def remember_expires_at : Time
        Time.utc + Devise.remember_for
      end

      def remember_me?(token : String, generated_at : String) : Bool
        # Full sub-second precision (the cookie carries "%f" ≈ µs): a ms-
        # truncated Time.unix_ms parse loses the fraction PG keeps in
        # remember_created_at, making `gen > remember_created_at` flaky
        # when both calls land in the same millisecond.
        secs = generated_at.to_f
        gen = Time.unix(secs.to_i64) + Time::Span.new(nanoseconds: ((secs % 1) * 1_000_000_000).to_i64)
        (Time.utc - Devise.remember_for < gen) &&
          (remember_created_at.nil? ? false : gen > remember_created_at.not_nil!) &&
          Devise.secure_compare(authenticatable_salt.to_s, token)
      end

      def self.serialize_into_cookie(record : self) : {Array(Int64), String, String}
        {[record.id.not_nil!], record.authenticatable_salt.not_nil!, ("%f" % Time.utc.to_unix_f)}
      end

      def self.serialize_from_cookie(key : Array(Int64), token : String, generated_at : String) : self?
        record = find?(key.first || raise ArgumentError.new("empty cookie key"))
        record.try do |r|
          r.remember_me?(token, generated_at) ? r : nil
        end
      end
    {% end %}

    # P1 modules (recoverable/confirmable/trackable/lockable/timeoutable)
    # are emitted by the second-stage macro in models_p1.cr.
    devise_p1({{modules}})

    # P2 omniauthable (omniauth_providers / from_omniauth) — omniauth.cr.
    devise_omniauthable({{modules}}, {{options}})
  end
end
