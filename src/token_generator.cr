# Devise::TokenGenerator + friendly_token — byte-compatible with the gem
# (devise 4.9.4): key derivation is PBKDF2-HMAC-SHA1 (65536 iterations,
# 64 bytes, salt "Devise <column>" — the ActiveSupport::KeyGenerator
# default), the stored value is HMAC-SHA256 hexdigest of the raw token.
# Verified against the gem: oracle case tok_digest_fixed matches.

require "openssl"
require "openssl/hmac"
require "random/secure"
require "base64"

module Devise
  # SecureRandom.urlsafe_base64(15).tr('lIO0', 'sxyz') — 20 chars.
  def self.friendly_token(length : Int32 = 20) : String
    rlength = (length * 3) // 4
    Random::Secure.base64(rlength)
      .gsub('+', '-')
      .gsub('/', '_')
      .tr("lIO0", "sxyz")
  end

  class TokenGenerator
    ITERATIONS = 65536
    KEY_SIZE   = 64

    def initialize(@secret : String)
    end

    def digest(column : String, value : String?) : String?
      return nil if value.nil? || value.empty?
      OpenSSL::HMAC.hexdigest(:sha256, key_for(column), value)
    end

    # Returns {raw, enc}; regenerates while the digest is already taken.
    def generate(model : ActiveRecord::Base.class, column : String) : {String, String}
      loop do
        raw = Devise.friendly_token
        enc = digest(column, raw).not_nil!
        unless model.where("#{column} = ?", enc).first?
          return {raw, enc}
        end
      end
    end

    private def key_for(column : String) : Slice(UInt8)
      OpenSSL::PKCS5.pbkdf2_hmac_sha1(@secret, "Devise #{column}", ITERATIONS, KEY_SIZE)
    end
  end

  class_property secret_key : String? = nil

  class_property? token_generator_set = false

  @@token_generator : TokenGenerator?

  def self.token_generator : TokenGenerator
    @@token_generator ||= begin
      secret = secret_key || raise ArgumentError.new(
        "Devise.secret_key is not set. Configure it in config/initializers/devise.cr")
      TokenGenerator.new(secret)
    end
  end

  def self.token_generator=(generator : TokenGenerator)
    @@token_generator = generator
    self.token_generator_set = true
  end

  def self.reset_token_generator : Nil
    @@token_generator = nil
    self.token_generator_set = false
  end
end
