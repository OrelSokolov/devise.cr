# JWT — HS256 access/refresh token pair with rotation (the Iteration 6
# addition for API/PWA/service tokens; not a gem port — Rails has no
# built-in JWT — so the contract is our own, covered by unit specs and
# cross-checked against the ruby-jwt wire format).
#
#   access token  : short-lived JWT {sub, iat, exp, jti}
#   refresh token : opaque random string, SHA256-hashed in
#                   devise_refresh_tokens; rotation revokes the old row.

require "openssl"
require "random/secure"
require "digest/sha256"
require "json"
require "base64"

module Devise
  module JWT
    class Error < Exception
    end

    class TokenInvalid < Error
    end

    class TokenExpired < Error
    end

    DEFAULT_ACCESS_TTL  = 15.minutes
    DEFAULT_REFRESH_TTL = 30.days

    class_property secret : String = "development-secret"
    class_property access_ttl : Time::Span = DEFAULT_ACCESS_TTL
    class_property refresh_ttl : Time::Span = DEFAULT_REFRESH_TTL

    # --- wire format --------------------------------------------------------

    private def self.base64url(data : Bytes) : String
      Base64.strict_encode(data).tr("+/", "-_").rstrip('=')
    end

    private def self.base64url_decode(part : String) : Bytes
      padded = part.tr("-_", "+/")
      padded += "=" * ((4 - padded.size % 4) % 4)
      Base64.decode(padded)
    end

    def self.encode(payload : Hash(String, JSON::Any | String | Int64 | Float64 | Nil)) : String
      header = base64url(%({"alg":"HS256","typ":"JWT"}).to_slice)
      body = base64url(payload.to_json.to_slice)
      signature = OpenSSL::HMAC.digest(:sha256, class_secret_bytes, "#{header}.#{body}".to_slice)
      "#{header}.#{body}.#{base64url(signature)}"
    end

    # Decodes and verifies signature + exp; raises TokenExpired /
    # TokenInvalid.
    def self.decode(token : String) : Hash(String, JSON::Any)
      parts = token.split('.')
      raise TokenInvalid.new unless parts.size == 3

      header, body, signature = parts
      expected = base64url(OpenSSL::HMAC.digest(:sha256, class_secret_bytes, "#{header}.#{body}".to_slice))
      raise TokenInvalid.new unless Devise.secure_compare(signature, expected)

      payload = Hash(String, JSON::Any).from_json(String.new(base64url_decode(body)))
      if (exp = payload["exp"]?) && (exp_num = exp.as_i64?)
        raise TokenExpired.new if Time.unix(exp_num) < Time.utc
      end
      payload
    end

    private def self.class_secret_bytes : Bytes
      JWT.secret.to_slice
    end

    # --- access / refresh pair ------------------------------------------------

    def self.issue_access(user_id : Int64) : String
      now = Time.utc
      encode({
        "sub" => user_id.to_s,
        "iat" => now.to_unix,
        "exp" => (now + JWT.access_ttl).to_unix,
        "jti" => Random::Secure.hex(12),
      } of String => JSON::Any | String | Int64 | Float64 | Nil)
    end

    def self.issue_refresh(user_id : Int64) : String
      token = Random::Secure.hex(32)
      now = Time.utc
      ActiveRecord::Base.connection.exec(
        "INSERT INTO devise_refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4)",
        args: [user_id, Digest::SHA256.hexdigest(token), now + JWT.refresh_ttl, now]
      )
      token
    end

    def self.issue_pair(user_id : Int64) : {access: String, refresh: String}
      {access: issue_access(user_id), refresh: issue_refresh(user_id)}
    end

    # Rotation: consumes the refresh token (revokes its row) and returns
    # a fresh access/refresh pair. A revoked/expired token raises
    # TokenInvalid.
    def self.refresh(refresh_token : String) : {access: String, refresh: String, user_id: Int64}
      token_hash = Digest::SHA256.hexdigest(refresh_token)
      rows = [] of {id: Int64, user_id: Int64, expires_at: Time, revoked_at: Time?}

      ActiveRecord::Base.connection.query(
        "SELECT id, user_id, expires_at, revoked_at FROM devise_refresh_tokens WHERE token_hash = $1",
        args: [token_hash]
      ) do |rs|
        rs.each do
          rows << {
            id:         rs.read(Int64),
            user_id:    rs.read(Int64),
            expires_at: rs.read(Time),
            revoked_at: rs.read(Time?),
          }
        end
      end

      row = rows.first? || raise(TokenInvalid.new("unknown refresh token"))
      raise TokenInvalid.new("revoked") if row[:revoked_at]
      raise TokenInvalid.new("expired") if row[:expires_at] < Time.utc

      ActiveRecord::Base.connection.exec(
        "UPDATE devise_refresh_tokens SET revoked_at = $1 WHERE id = $2",
        args: [Time.utc, row[:id]]
      )
      pair = issue_pair(row[:user_id])
      {access: pair[:access], refresh: pair[:refresh], user_id: row[:user_id]}
    end
  end
end
