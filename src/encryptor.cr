# Devise::Encryptor — bcrypt with pepper, byte-compatible with the gem
# (verified cross-check: Ruby BCrypt hashes rehash identically here).

require "crypto/bcrypt"
require "crypto/subtle"

module Devise
  module Encryptor
    # digest(klass, password) in the gem; klass supplies pepper/stretches.
    # Ruby's bcrypt silently uses the first 72 bytes; Crystal's raises at 72
    # (it appends a NUL byte), so the practical cap is 71. Byte-identical to
    # the gem for every password < 72 bytes (documented deviation).
    def self.digest(pepper : String?, stretches : Int32, password : String) : String
      peppered = (pepper.presence ? "#{password}#{pepper}" : password).byte_slice(0, 71)
      Crypto::Bcrypt::Password.create(peppered, cost: stretches).to_s
    end

    def self.compare(pepper : String?, hashed_password : String, password : String) : Bool
      return false if hashed_password.empty?
      begin
        bcrypt = Crypto::Bcrypt::Password.new(hashed_password)
      rescue Crypto::Bcrypt::Error
        return false
      end
      peppered = (pepper.presence ? "#{password}#{pepper}" : password).byte_slice(0, 71)
      rehashed = Crypto::Bcrypt.new(peppered, bcrypt.salt, bcrypt.cost).to_s
      Devise.secure_compare(rehashed, hashed_password)
    end
  end

  def self.secure_compare(a : String, b : String) : Bool
    return false unless a.bytesize == b.bytesize
    Crypto::Subtle.constant_time_compare(a, b)
  end
end
