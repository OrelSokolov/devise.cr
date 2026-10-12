# Devise::OmniAuth — P2 omniauthable support.
#
# Two parts, both ported 1:1 and verified against the oracle
# (oracle/omniauth_cases.rb ↔ oracle/omniauth_expected.yml):
#
#   * the OmniAuth AuthHash schema (omniauth 2.1.3): provider/uid/info/
#     credentials/extra with InfoHash#name fallback chain
#     (name → "first last" → nickname → email → nil);
#   * the google_oauth2 strategy (omniauth-google-oauth2 1.1.1):
#     scope normalization (BASE_SCOPES + URL prefixing), authorize
#     params (access_type=offline default, hex-48 state) and the
#     AuthHash building rules (uid=sub, email only when email_verified,
#     prune of nil/empty values).
#
# The OAuth2 wire client (authorize redirect → code → token exchange →
# userinfo) is stdlib-only (HTTP::Client) — no external shards, per the
# repository's component-independence rule. There is no Crystal omniauth
# shard with the AuthHash contract (multi_auth has its own User schema).

require "http/client"
require "json"
require "random/secure"
require "uri"

module Devise
  module OmniAuth
    # Common surface of an OAuth2 provider client, as used by the HTTP
    # layer (request phase redirect + callback phase). Both bundled
    # strategies (GoogleOauth2, GitHub) conform.
    module Strategy
      abstract def authorize_url(redirect_uri : String) : String
      abstract def authenticate(code : String, redirect_uri : String) : AuthHash
    end

    class Error < Exception
    end

    # OmniAuth::AuthHash::InfoHash — the normalized `info` subhash.
    class Info
      property name : String? = nil
      property nickname : String? = nil
      property email : String? = nil
      property first_name : String? = nil
      property last_name : String? = nil
      property image : String? = nil
      property urls : Hash(String, String) = {} of String => String

      # google_oauth2 strategy additions (omniauth-google-oauth2 info block)
      property email_verified : Bool? = nil
      property unverified_email : String? = nil

      def initialize(name : String? = nil, email : String? = nil,
                     first_name : String? = nil, last_name : String? = nil,
                     nickname : String? = nil, image : String? = nil)
        @name = name
        @email = email
        @first_name = first_name
        @last_name = last_name
        @nickname = nickname
        @image = image
      end

      # InfoHash#name: name → "first_name last_name".strip → nickname →
      # email → nil (oracle: oa_auth_hash_name_fallback).
      def resolved_name : String?
        return name unless name.nil?
        return "#{first_name.to_s} #{last_name.to_s}".strip unless first_name.nil? && last_name.nil?
        return nickname unless nickname.nil?
        email
      end

      # InfoHash#valid? — a name must be resolvable.
      def valid? : Bool
        !resolved_name.nil?
      end

      # to_hash: pruned fields plus the resolved name (InfoHash#to_hash
      # sets hash['name'] ||= name).
      def to_h : Hash(String, JSON::Any)
        h = {} of String => JSON::Any
        put(h, "name", resolved_name)
        put(h, "nickname", nickname)
        put(h, "email", email)
        put(h, "email_verified", email_verified)
        put(h, "unverified_email", unverified_email)
        put(h, "first_name", first_name)
        put(h, "last_name", last_name)
        put(h, "image", image)
        h["urls"] = JSON::Any.new(urls.reject { |_, v| v.empty? }.transform_values { |v| JSON::Any.new(v) }) unless urls.empty?
        h
      end

      private def put(h : Hash(String, JSON::Any), key : String, value : String?) : Nil
        h[key] = JSON::Any.new(value) if value && !value.empty?
      end

      private def put(h : Hash(String, JSON::Any), key : String, value : Bool?) : Nil
        h[key] = JSON::Any.new(value) unless value.nil?
      end

      def to_json(json : JSON::Builder)
        to_h.to_json(json)
      end
    end

    # OAuth2 strategy credentials block (+ google's scope key).
    class Credentials
      property token : String? = nil
      property refresh_token : String? = nil
      property expires : Bool = false
      property expires_at : Int64? = nil
      property scope : String? = nil

      def to_h : Hash(String, JSON::Any)
        h = {} of String => JSON::Any
        h["token"] = JSON::Any.new(token) unless token.nil? || token.try(&.empty?)
        if refresh = refresh_token
          h["refresh_token"] = JSON::Any.new(refresh) if expires && !refresh.empty?
        end
        h["expires_at"] = JSON::Any.new(expires_at) if expires && expires_at
        h["expires"] = JSON::Any.new(expires)
        if s = scope
          h["scope"] = JSON::Any.new(s) unless s.empty?
        end
        h
      end

      def to_json(json : JSON::Builder)
        to_h.to_json(json)
      end
    end

    class Extra
      property id_token : String? = nil
      property raw_info : Hash(String, JSON::Any)? = nil
      # github strategy additions (omniauth-github 2.0.1 extra block):
      # all_emails is always written ([] without email scope) and scope
      # is written even when null.
      property all_emails : Array(Hash(String, JSON::Any))? = nil
      property scope : JSON::Any? = nil

      def to_h : Hash(String, JSON::Any)
        h = {} of String => JSON::Any
        if id = id_token
          h["id_token"] = JSON::Any.new(id) unless id.empty?
        end
        h["raw_info"] = JSON::Any.new(raw_info) if raw_info && !raw_info.try(&.empty?)
        if emails = all_emails
          h["all_emails"] = JSON::Any.new(emails.map { |e| JSON::Any.new(e) })
        end
        if s = scope
          h["scope"] = s # Any(null) is written as null; plain nil skips the key
        end
        h
      end

      def to_json(json : JSON::Builder)
        to_h.to_json(json)
      end
    end

    # OmniAuth::AuthHash — the normalized schema returned by all
    # strategies. valid? = provider + uid + resolvable info name.
    class AuthHash      property provider : String = ""
      property uid : String = ""
      property info : Info = Info.new
      property credentials : Credentials? = nil
      property extra : Extra? = nil

      def initialize(provider : String = "", uid : String = "", info : Info = Info.new)
        @provider = provider
        @uid = uid
        @info = info
      end

      def valid? : Bool
        !uid.empty? && !provider.empty? && info.valid?
      end

      def to_h : Hash(String, JSON::Any)
        h = {} of String => JSON::Any
        h["provider"] = JSON::Any.new(provider)
        h["uid"] = JSON::Any.new(uid)
        h["info"] = JSON::Any.new(info.to_h)
        if (c = credentials) && !c.to_h.empty?
          h["credentials"] = JSON::Any.new(c.to_h)
        end
        if (e = extra) && !e.to_h.empty?
          h["extra"] = JSON::Any.new(e.to_h)
        end
        h
      end
    end

    # Parsed token-endpoint response. `expires?` mirrors OAuth2::AccessToken
    # (expires when the response carried expires_in).
    class Token
      property access_token : String
      property refresh_token : String? = nil
      property id_token : String? = nil
      property expires_in : Int32? = nil
      property scope : String? = nil

      def initialize(@access_token); end

      def expires? : Bool
        !expires_in.nil?
      end
    end

    # google_oauth2 strategy — authorize URL, token exchange and
    # userinfo/AuthHash building, 1:1 with omniauth-google-oauth2 1.1.1.
    # Endpoints are properties so specs (and tests against a stub
    # provider) can redirect them.
    class GoogleOauth2
      include Strategy

      ALLOWED_ISSUERS     = {"accounts.google.com", "https://accounts.google.com"}
      BASE_SCOPE_URL      = "https://www.googleapis.com/auth/"
      BASE_SCOPES         = %w(profile email openid)
      DEFAULT_SCOPE       = "email,profile"
      USER_INFO_URL       = "https://www.googleapis.com/oauth2/v3/userinfo"
      DEFAULT_SITE        = "https://oauth2.googleapis.com"
      DEFAULT_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth"
      DEFAULT_TOKEN_PATH  = "/token"

      getter client_id : String
      getter client_secret : String

      property site           : String = DEFAULT_SITE
      property authorize_url  : String = DEFAULT_AUTHORIZE_URL
      property token_path     : String = DEFAULT_TOKEN_PATH
      property user_info_url  : String = USER_INFO_URL

      def initialize(@client_id : String, @client_secret : String)
      end

      # get_scope 1:1: split on spaces then commas; keep http(s) URLs and
      # BASE_SCOPES as-is, prefix everything else with BASE_SCOPE_URL.
      # "email,profile" → "email profile", "calendar" →
      # "https://www.googleapis.com/auth/calendar" (oracle: g_scope_*).
      def self.get_scope(scope : String?) : String
        list = (scope || DEFAULT_SCOPE).split(' ').flat_map &.split(',')
        list.map! do |s|
          if s.starts_with?("http://") || s.starts_with?("https://") || BASE_SCOPES.includes?(s)
            s
          else
            "#{BASE_SCOPE_URL}#{s}"
          end
        end
        list.join(' ')
      end

      # authorize_params + authorize_url. Mirrors the strategy defaults:
      # response_type=code, access_type=offline unless given, 48-hex
      # state (SecureRandom.hex(24)) unless given (oracle:
      # g_access_type_default, g_state_in_session, g_authorize_url_full).
      def authorize_url(redirect_uri : String, scope : String? = nil, state : String? = nil,
                        access_type : String? = nil, hd : String? = nil,
                        login_hint : String? = nil, prompt : String? = nil) : String
        params = {
          "client_id"     => client_id,
          "redirect_uri"  => redirect_uri,
          "response_type" => "code",
          "scope"         => GoogleOauth2.get_scope(scope),
          "access_type"   => access_type || "offline",
          "state"         => state || Random::Secure.hex(24),
        } of String => String
        params["hd"] = hd if hd
        params["login_hint"] = login_hint if login_hint
        params["prompt"] = prompt if prompt
        "#{authorize_url}?#{URI::Params.encode(params)}"
      end

      # POST /token (authorization_code grant), like OAuth2::Client
      # auth_code.get_token.
      def token(code : String, redirect_uri : String) : Token
        response = HTTP::Client.post("#{site}#{token_path}", form: {
          "client_id"     => client_id,
          "client_secret" => client_secret,
          "code"          => code,
          "grant_type"    => "authorization_code",
          "redirect_uri"  => redirect_uri,
        })
        unless response.status.success?
          raise Error.new("token exchange failed: HTTP #{response.status_code}")
        end
        json = JSON.parse(response.body)
        if error = json["error"]?
          raise Error.new(error.to_s)
        end
        t = Token.new(json["access_token"].as_s)
        t.refresh_token = json["refresh_token"]?.try(&.as_s?)
        t.id_token = json["id_token"]?.try(&.as_s?)
        t.expires_in = json["expires_in"]?.try(&.as_i?)
        t.scope = json["scope"]?.try(&.as_s?)
        t
      end

      # GET userinfo with the bearer token (raw_info).
      def userinfo(access_token : String) : Hash(String, JSON::Any)
        response = HTTP::Client.get(user_info_url, headers: HTTP::Headers{
          "Authorization" => "Bearer #{access_token}",
        })
        unless response.status.success?
          raise Error.new("userinfo failed: HTTP #{response.status_code}")
        end
        JSON.parse(response.body).as_h
      end

      # Full callback phase: code → token → userinfo → AuthHash.
      def authenticate(code : String, redirect_uri : String) : AuthHash
        t = token(code, redirect_uri)
        auth_hash(t, userinfo(t.access_token))
      end

      # The AuthHash assembled from a token response + raw_info
      # (oracle: g_hash_verified, g_hash_unverified_email, g_hash_no_name,
      # g_hash_uid_sub): uid = sub, email only when email_verified,
      # prune of nil/empty values.
      def auth_hash(token : Token, raw_info : Hash(String, JSON::Any),
                    token_scope : String? = token.scope) : AuthHash
        hash = AuthHash.new
        hash.provider = "google_oauth2"
        hash.uid = str(raw_info, "sub").to_s

        info = Info.new
        info.name = str(raw_info, "name")
        info.email_verified = bool(raw_info, "email_verified")
        info.email = info.email_verified ? str(raw_info, "email") : nil
        info.unverified_email = str(raw_info, "email")
        info.first_name = str(raw_info, "given_name")
        info.last_name = str(raw_info, "family_name")
        info.image = str(raw_info, "picture")
        if profile = str(raw_info, "profile")
          info.urls = {"google" => profile}
        end
        hash.info = info

        credentials = Credentials.new
        credentials.token = token.access_token
        if token.expires? && (refresh = token.refresh_token)
          credentials.refresh_token = refresh
        end
        credentials.expires = token.expires?
        credentials.expires_at = Time.utc.to_unix + token.expires_in.not_nil! if token.expires?
        credentials.scope = token_scope.presence
        hash.credentials = credentials

        extra = Extra.new
        extra.id_token = token.id_token || token.access_token
        extra.raw_info = raw_info
        hash.extra = extra

        hash
      end

      private def str(raw : Hash(String, JSON::Any), key : String) : String?
        raw[key]?.try(&.as_s?)
      end

      private def bool(raw : Hash(String, JSON::Any), key : String) : Bool?
        raw[key]?.try do |v|
          v.as_bool? || v.as_s? == "true"
        end
      end
    end

    # github strategy — 1:1 with omniauth-github 2.0.1: client endpoints,
    # no default scope, uid = raw_info['id'], email from /user/emails when
    # the configured scope allows it (primary+verified) else raw_info email,
    # extra carries all_emails + token scope (null when absent).
    class GitHub
      include Strategy

      DEFAULT_SITE         = "https://api.github.com"
      DEFAULT_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
      DEFAULT_TOKEN_URL    = "https://github.com/login/oauth/access_token"
      EMAIL_SCOPES         = %w(user user:email)

      getter client_id : String
      getter client_secret : String
      # The configured (strategy options) scope — drives the email access
      # decision, exactly like the gem's options['scope'].
      property scope : String? = nil

      property site          : String = DEFAULT_SITE
      property authorize_url : String = DEFAULT_AUTHORIZE_URL
      property token_url     : String = DEFAULT_TOKEN_URL

      def initialize(@client_id : String, @client_secret : String, @scope : String? = nil)
      end

      def email_access_allowed? : Bool
        s = scope
        return false unless s
        (s.split(',') & EMAIL_SCOPES).any?
      end

      # authorize_params 1:1: response_type=code, scope only when
      # configured (GitHub has no client-side default), 48-hex state.
      def authorize_url(redirect_uri : String, scope : String? = nil,
                        state : String? = nil) : String
        params = {
          "client_id"     => client_id,
          "redirect_uri"  => redirect_uri,
          "response_type" => "code",
          "state"         => state || Random::Secure.hex(24),
        } of String => String
        if effective_scope = (scope || self.scope)
          params["scope"] = effective_scope
        end
        "#{authorize_url}?#{URI::Params.encode(params)}"
      end

      # POST token_url (authorization_code grant). GitHub answers JSON
      # when asked to (Accept header), like the oauth2 gem's default.
      def token(code : String, redirect_uri : String) : Token
        response = HTTP::Client.post(token_url, form: {
          "client_id"     => client_id,
          "client_secret" => client_secret,
          "code"          => code,
          "grant_type"    => "authorization_code",
          "redirect_uri"  => redirect_uri,
        }, headers: HTTP::Headers{"Accept" => "application/json"})
        unless response.status.success?
          raise Error.new("token exchange failed: HTTP #{response.status_code}")
        end
        json = JSON.parse(response.body)
        if error = json["error"]?
          raise Error.new(error.to_s)
        end
        t = Token.new(json["access_token"].as_s)
        t.refresh_token = json["refresh_token"]?.try(&.as_s?)
        t.expires_in = json["expires_in"]?.try(&.as_i?)
        t.scope = json["scope"]?.try(&.as_s?)
        t
      end

      # GET /user with the bearer token (header mode, raw_info).
      def user(access_token : String) : Hash(String, JSON::Any)
        api_get(site, "/user", access_token).as_h
      end

      # GET /user/emails — only meaningful with email scope (the gem
      # returns [] without even calling the endpoint).
      def emails(access_token : String) : Array(Hash(String, JSON::Any))
        return [] of Hash(String, JSON::Any) unless email_access_allowed?
        raw = api_get(site, "/user/emails", access_token,
          accept: "application/vnd.github.v3+json")
        raw.as_a.map(&.as_h)
      end

      # The first primary+verified entry of /user/emails, else nil.
      def primary_email(all_emails : Array(Hash(String, JSON::Any))) : String?
        entry = all_emails.find do |e|
          truthy?(e, "primary") && truthy?(e, "verified")
        end
        entry.try(&.["email"]?).try(&.as_s?)
      end

      # Full callback phase: code → token → user (+emails) → AuthHash.
      def authenticate(code : String, redirect_uri : String) : AuthHash
        t = token(code, redirect_uri)
        auth_hash(t, user(t.access_token), emails(t.access_token))
      end

      # The AuthHash assembled from a token response + raw_info + emails
      # (oracle: gh_hash_user, gh_hash_no_email_scope, gh_hash_uid):
      # uid = raw_info['id'], email via primary_email when the scope
      # allows else raw_info['email'], extra = raw_info + all_emails +
      # token scope (null when absent).
      def auth_hash(token : Token, raw_info : Hash(String, JSON::Any),
                    all_emails : Array(Hash(String, JSON::Any))) : AuthHash
        hash = AuthHash.new
        hash.provider = "github"
        hash.uid = raw_info["id"]?.try { |v| v.as_i? || v.as_s? }.to_s

        info = Info.new
        info.nickname = str(raw_info, "login")
        info.email = email_access_allowed? ? primary_email(all_emails) : str(raw_info, "email")
        info.name = str(raw_info, "name")
        info.image = str(raw_info, "avatar_url")
        urls = {} of String => String
        if github = str(raw_info, "html_url")
          urls["GitHub"] = github
        end
        if blog = str(raw_info, "blog")
          urls["Blog"] = blog
        end
        info.urls = urls
        hash.info = info

        credentials = Credentials.new
        credentials.token = token.access_token
        credentials.expires = token.expires?
        credentials.expires_at = Time.utc.to_unix + token.expires_in.not_nil! if token.expires?
        hash.credentials = credentials

        extra = Extra.new
        extra.raw_info = raw_info
        extra.all_emails = all_emails
        extra.scope = JSON::Any.new(token.scope)
        hash.extra = extra

        hash
      end

      private def api_get(base : String, path : String, access_token : String,
                          accept : String? = nil) : JSON::Any
        headers = HTTP::Headers{"Authorization" => "Bearer #{access_token}"}
        headers["Accept"] = accept if accept
        response = HTTP::Client.get("#{base}#{path}", headers: headers)
        unless response.status.success?
          raise Error.new("GET #{path} failed: HTTP #{response.status_code}")
        end
        JSON.parse(response.body)
      end

      private def truthy?(raw : Hash(String, JSON::Any), key : String) : Bool
        raw[key]?.try { |v| v.as_bool? || v.as_s? == "true" } || false
      end

      private def str(raw : Hash(String, JSON::Any), key : String) : String?
        raw[key]?.try(&.as_s?)
      end
    end
  end
end

# The omniauthable module of the `devise` macro: omniauth_providers
# config, devise_modules and the canonical from_omniauth (the devise
# generator idiom: find by provider+uid, else create with a
# friendly_token password). Invoked from models.cr with the macro's
# module list and named options.
class ActiveRecord::Base
  macro devise_omniauthable(modules, options)
    {% has_omniauthable = modules.includes?(:omniauthable) %}
    {% if options.is_a?(NamedTupleLiteral) && options.keys.map(&.stringify).includes?("omniauth_providers") %}
      {% providers = options[:omniauth_providers] %}
    {% else %}
      {% providers = nil %}
    {% end %}

    def self.devise_modules : Array(Symbol)
      [{{ modules.splat }}] of Symbol
    end

    {% if has_omniauthable %}
      def self.omniauth_providers : Array(Symbol)
        {% if providers %}
          [{{ providers.splat }}] of Symbol
        {% else %}
          [] of Symbol
        {% end %}
      end

      def self.from_omniauth(auth : Devise::OmniAuth::AuthHash) : self
        if existing = where("provider = ? AND uid = ?", auth.provider, auth.uid).first?
          return existing
        end
        record = new(for_load: false)
        values = {} of String => ::ActiveRecord::Value
        if info = auth.info
          values["email"] = info.email || ""
          values["name"] = info.name if info.name
          values["image"] = info.image if info.image
        end
        values["provider"] = auth.provider
        values["uid"] = auth.uid
        record.assign_attributes(values)
        record.password = Devise.friendly_token[0, 20]
        record.save!
        record
      end
    {% end %}
  end
end
