# Oracle spec for omniauthable (P2): the Crystal port must reproduce
# oracle/omniauth_expected.yml exactly (captured from devise 4.9.4 +
# omniauth 2.1.3 + omniauth-google-oauth2 1.1.1). Same case IDs, no
# edits; values use the same \n/\t escape protocol as oracle_spec.cr.

require "spec"
require "crypto/bcrypt"
require "../src/devise_cr"

OA_EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/omniauth_expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

def oa_escape(s : String | Bool) : String
  s = s.to_s
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

OA_TEST_URL = ENV["DEVISE_TEST_URL"]? ||
           "postgres://root@/crails_as_test?host=/var/run/postgresql"

ActiveRecord::Base.establish_connection(OA_TEST_URL)
ActiveRecord::Base.connection.exec("DELETE FROM oauth_users")

class OauthUser < ActiveRecord::Base
  set_table_name "oauth_users"
  devise :database_authenticatable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: [:google_oauth2]
end

class PlainOauthUser < ActiveRecord::Base
  set_table_name "oauth_users"
  devise :omniauthable
end



AUTH = Devise::OmniAuth::AuthHash.new(
  provider: "google_oauth2",
  uid: "1000000000000000001",
  info: Devise::OmniAuth::Info.new(
    name: "Test User",
    email: "test@example.com",
    image: "https://lh3.googleusercontent.com/a-/photo.jpg"))

# Recursively sorted JSON rendering — mirrors the oracle's sorted()/
# JSON.generate so key order never matters.
def sorted_json(value) : String
  String.build do |io|
    JSON.build(io) do |json|
      write_sorted(json, value)
    end
  end
end

def write_sorted(json : JSON::Builder, value) : Nil
  raw = value.is_a?(JSON::Any) ? value.raw : value
  case raw
  when Hash
    json.object do
      raw.keys.sort.each do |k|
        json.field(k) { write_sorted(json, raw[k]) }
      end
    end
  when Array
    json.array do
      raw.each { |v| write_sorted(json, v) }
    end
  else
    raw.to_json(json)
  end
end

def raw_info_hash(h : Hash(String, String | Bool)) : Hash(String, JSON::Any)
  h.transform_values { |v| JSON::Any.new(v) }
end

# Mirror of the oracle strategy stub: a strategy whose token exchange
# and userinfo are replaced by fixed payloads (site/client stay real).
def stub_strategy(raw_info : Hash(String, JSON::Any), scope : String? = "email profile")
  Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
end

RAW_INFO = raw_info_hash({
  "sub"            => "1000000000000000001",
  "name"           => "Test User",
  "given_name"     => "Test",
  "family_name"    => "User",
  "picture"        => "https://lh3.googleusercontent.com/a-/photo.jpg",
  "email"          => "test@example.com",
  "email_verified" => true,
  "profile"        => "https://plus.google.com/1000000000000000001",
})

def fake_token : Devise::OmniAuth::Token
  Devise::OmniAuth::Token.new("ya29.access.token")
end

def strategy_auth_hash(raw_info : Hash(String, JSON::Any), scope : String?)
  strategy = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
  token = fake_token
  token.scope = scope
  strategy.auth_hash(token, raw_info)
end

GH_RAW_INFO = JSON.parse(<<-JSON
  {"login":"testuser","id":38758392,"name":"Test User",
   "avatar_url":"https://avatars.githubusercontent.com/u/38758392?v=4",
   "html_url":"https://github.com/testuser",
   "blog":"https://blog.example.com","email":"public@example.com"}
  JSON
).as_h

GH_EMAILS = JSON.parse(<<-JSON
  [{"email":"primary@example.com","primary":true,"verified":true},
   {"email":"other@example.com","primary":false,"verified":true}]
  JSON
).as_a.map(&.as_h)

# Mirror of the oracle github stub: token/user/emails payloads with the
# strategy's scope driving the email access decision.
def gh_auth_hash(scope : String?, all_emails : Array(Hash(String, JSON::Any)))
  strategy = Devise::OmniAuth::GitHub.new("appid", "secret", scope: scope)
  token = Devise::OmniAuth::Token.new("ghu.access.token")
  token.scope = scope
  strategy.auth_hash(token, GH_RAW_INFO, all_emails)
end

OA_CASES = {
  # --- modules / providers ---
  "oa_modules"           => -> { OauthUser.devise_modules.includes?(:omniauthable).to_s },
  "oa_providers"         => -> { OauthUser.omniauth_providers.inspect },
  "oa_providers_default" => -> { PlainOauthUser.omniauth_providers.inspect },
  # --- Devise.friendly_token ---
  "oa_friendly_token_shape" => -> {
    t = Devise.friendly_token
    [t.size == 20, t.matches?(/\A[A-Za-z0-9_-]+\z/), t.count("lIO0").zero?].inspect
  },
  "oa_friendly_token_len" => -> { (Devise.friendly_token(32).size == 32).to_s },
  # --- from_omniauth (generated idiom) ---
  "oa_from_create" => -> {
    u = OauthUser.from_omniauth(AUTH)
    [u.persisted?, u.provider, u.uid, u.email, u.name,
     u.encrypted_password.to_s.matches?(/^\$2a\$12\$[.\/A-Za-z0-9]{53}$/)].inspect
  },
  "oa_from_idempotent" => -> {
    a = OauthUser.from_omniauth(AUTH)
    b = OauthUser.from_omniauth(AUTH)
    [a.id == b.id, OauthUser.count == 1].inspect
  },
  "oa_from_new_uid" => -> {
    other = Devise::OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "42",
                                   info: Devise::OmniAuth::Info.new(email: "other@example.com"))
    u = OauthUser.from_omniauth(other)
    [u.persisted?, u.uid, OauthUser.count == 2].inspect
  },
  "oa_oauth_user_valid" => -> {
    u = OauthUser.from_omniauth(AUTH)
    u.name = "Renamed"
    [u.valid?, u.errors.empty?].inspect
  },
  # --- Devise::OmniAuth::AuthHash schema ---
  "oa_auth_hash_valid" => -> {
    Devise::OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1",
                           info: Devise::OmniAuth::Info.new(name: "X", email: "x@e.co")).valid?.to_s
  },
  "oa_auth_hash_invalid_no_name" => -> {
    Devise::OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1",
                           info: Devise::OmniAuth::Info.new(email: "x@e.co")).valid?.to_s
  },
  "oa_auth_hash_invalid_empty_info" => -> {
    Devise::OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1").valid?.to_s
  },
  "oa_auth_hash_name_fallback" => -> {
    [
      Devise::OmniAuth::Info.new(first_name: "A", last_name: "B").resolved_name,
      Devise::OmniAuth::Info.new(nickname: "nick").resolved_name,
      Devise::OmniAuth::Info.new(email: "e@x.co").resolved_name,
      Devise::OmniAuth::Info.new.resolved_name,
    ].inspect
  },
  # --- google_oauth2 strategy ---
  "g_client_site"   => -> { Devise::OmniAuth::GoogleOauth2.new("appid", "secret").site },
  "g_authorize_url" => -> { Devise::OmniAuth::GoogleOauth2.new("appid", "secret").authorize_url },
  "g_token_url"     => -> {
    s = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
    "#{s.site}#{s.token_path}"
  },
  "g_scope_default" => -> { Devise::OmniAuth::GoogleOauth2.get_scope(nil) },
  "g_scope_custom"  => -> { Devise::OmniAuth::GoogleOauth2.get_scope("profile,email,calendar") },
  "g_scope_url_untouched" => -> {
    Devise::OmniAuth::GoogleOauth2.get_scope("https://www.googleapis.com/auth/calendar.profile")
  },
  "g_access_type_default" => -> {
    s = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
    URI::Params.parse(URI.parse(s.authorize_url("http://cb")).query.not_nil!)["access_type"]
  },
  "g_state_in_session" => -> {
    s = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
    url = s.authorize_url("http://cb")
    state = URI::Params.parse(URI.parse(url).query.not_nil!)["state"]
    [state.matches?(/\A[0-9a-f]{48}\z/) != nil, state.size == 48].inspect
  },
  "g_authorize_url_full" => -> {
    s = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
    url = s.authorize_url("http://localhost:3000/users/auth/google_oauth2/callback")
    q = URI::Params.parse(URI.parse(url).query.not_nil!)
    pairs = q.to_a.reject { |k, _| k == "state" }.map { |k, v| [k, v] of String }
    (pairs << ({"state", q["state"].matches?(/\A[0-9a-f]{48}\z/) ? "hex48" : "bad"}.to_a)).sort.inspect
  },
  # --- google_oauth2 AuthHash (faked token/userinfo) ---
  "g_hash_verified" => -> {
    sorted_json(strategy_auth_hash(RAW_INFO, "email profile").to_h)
  },
  "g_hash_unverified_email" => -> {
    raw = RAW_INFO.dup
    raw["email_verified"] = JSON::Any.new(false)
    sorted_json(strategy_auth_hash(raw, "email profile").to_h)
  },
  "g_hash_no_name" => -> {
    raw = raw_info_hash({"sub" => "555", "email" => "noname@example.com",
                         "email_verified" => true})
    sorted_json(strategy_auth_hash(raw, "email profile").to_h)
  },
  "g_hash_uid_sub" => -> { strategy_auth_hash(RAW_INFO, nil).uid },
  # --- github strategy (omniauth-github 2.0.1) ---
  "gh_client_site"   => -> { Devise::OmniAuth::GitHub.new("appid", "secret").site },
  "gh_authorize_url" => -> { Devise::OmniAuth::GitHub.new("appid", "secret").authorize_url },
  "gh_token_url"     => -> { Devise::OmniAuth::GitHub.new("appid", "secret").token_url },
  "gh_scope_default" => -> {
    s = Devise::OmniAuth::GitHub.new("appid", "secret")
    URI::Params.parse(URI.parse(s.authorize_url("http://cb")).query.not_nil!)["scope"]?.inspect
  },
  "gh_scope_custom" => -> {
    s = Devise::OmniAuth::GitHub.new("appid", "secret", scope: "user,public_repo")
    URI::Params.parse(URI.parse(s.authorize_url("http://cb")).query.not_nil!)["scope"]
  },
  "gh_state_in_session" => -> {
    s = Devise::OmniAuth::GitHub.new("appid", "secret")
    state = URI::Params.parse(URI.parse(s.authorize_url("http://cb")).query.not_nil!)["state"]
    [state.matches?(/\A[0-9a-f]{48}\z/) != nil, state.size == 48].inspect
  },
  "gh_authorize_url_full" => -> {
    s = Devise::OmniAuth::GitHub.new("appid", "secret", scope: "user")
    url = s.authorize_url("http://localhost:3000/users/auth/github/callback")
    q = URI::Params.parse(URI.parse(url).query.not_nil!)
    pairs = q.to_a.reject { |k, _| k == "state" }.map { |k, v| [k, v] of String }
    (pairs << ({"state", q["state"].matches?(/\A[0-9a-f]{48}\z/) ? "hex48" : "bad"}.to_a)).sort.inspect
  },
  "gh_hash_user" => -> {
    sorted_json(gh_auth_hash("user", GH_EMAILS).to_h)
  },
  "gh_hash_no_email_scope" => -> {
    sorted_json(gh_auth_hash(nil, [] of Hash(String, JSON::Any)).to_h)
  },
  "gh_hash_uid" => -> { gh_auth_hash("user", GH_EMAILS).uid },
  "gh_email_access" => -> {
    %w[user user:email repo].map { |sc| Devise::OmniAuth::GitHub.new("a", "b", scope: sc).email_access_allowed? }.inspect
  },
}

describe "devise omniauth oracle" do
  OA_CASES.each do |id, block|
    it id do
      expected = OA_EXPECTED[id]? || fail("missing expected value for #{id}")
      oa_escape(block.call).should eq expected
    end
  end
end

# Unit specs beyond the oracle: the OAuth2 wire flow against a local
# stub provider (authorize URL → code → token → userinfo → AuthHash).
describe "google oauth2 wire flow" do
  it "exchanges the code and builds the auth hash" do
    server = HTTP::Server.new do |context|
      case {context.request.method, context.request.path}
      when {"POST", "/token"}
        form = URI::Params.parse(context.request.body.not_nil!.gets_to_end)
        form["client_id"].should eq("appid")
        form["grant_type"].should eq("authorization_code")
        context.response.content_type = "application/json"
        context.response.print <<-JSON
          {"access_token":"ya29.wire","expires_in":3599,
           "refresh_token":"1//rtoken","scope":"email profile",
           "id_token":"eyj.wire.sig"}
          JSON
      when {"GET", "/userinfo"}
        context.request.headers["Authorization"].should eq("Bearer ya29.wire")
        context.response.content_type = "application/json"
        context.response.print <<-JSON
          {"sub":"777","name":"Wire User","given_name":"Wire","family_name":"User",
           "email":"wire@example.com","email_verified":true,
           "picture":"https://lh3/p.jpg"}
          JSON
      else
        context.response.status_code = 404
      end
    end
    address = server.bind_tcp("127.0.0.1", 0)
    spawn { server.listen }

    begin
      strategy = Devise::OmniAuth::GoogleOauth2.new("appid", "secret")
      strategy.site = "http://#{address}"
      strategy.authorize_url = "http://#{address}/authorize"
      strategy.token_path = "/token"
      strategy.user_info_url = "http://#{address}/userinfo"

      redirect = "http://localhost:3000/users/auth/google_oauth2/callback"
      url = strategy.authorize_url(redirect)
      URI::Params.parse(URI.parse(url).query.not_nil!)["response_type"].should eq("code")

      auth = strategy.authenticate("wire-code", redirect)
      auth.provider.should eq("google_oauth2")
      auth.uid.should eq("777")
      auth.info.email.should eq("wire@example.com")
      auth.info.name.should eq("Wire User")
      auth.credentials.should_not be_nil
      auth.credentials.not_nil!.token.should eq("ya29.wire")
      auth.credentials.not_nil!.refresh_token.should eq("1//rtoken")
      auth.credentials.not_nil!.expires.should be_true
      auth.credentials.not_nil!.scope.should eq("email profile")
      auth.extra.not_nil!.id_token.should eq("eyj.wire.sig")
      auth.valid?.should be_true
    ensure
      server.close
    end
  end
end

# Same wire-flow unit for the github strategy: authorize → code → token →
# /user (+/user/emails) → AuthHash.
describe "github oauth2 wire flow" do
  it "exchanges the code and builds the auth hash" do
    server = HTTP::Server.new do |context|
      case {context.request.method, context.request.path}
      when {"POST", "/login/oauth/access_token"}
        form = URI::Params.parse(context.request.body.not_nil!.gets_to_end)
        form["client_id"].should eq("appid")
        form["grant_type"].should eq("authorization_code")
        context.response.content_type = "application/json"
        context.response.print %q({"access_token":"ghu.wire","scope":"user"})
      when {"GET", "/user"}
        context.request.headers["Authorization"].should eq("Bearer ghu.wire")
        context.response.content_type = "application/json"
        context.response.print %q({"login":"wireuser","id":999,"name":"Wire User",
          "avatar_url":"https://avatars.githubusercontent.com/u/999?v=4",
          "html_url":"https://github.com/wireuser","email":"public@wire.dev"})
      when {"GET", "/user/emails"}
        context.request.headers["Authorization"].should eq("Bearer ghu.wire")
        context.response.content_type = "application/json"
        context.response.print %q([{"email":"wire@wire.dev","primary":true,"verified":true}])
      else
        context.response.status_code = 404
      end
    end
    address = server.bind_tcp("127.0.0.1", 0)
    spawn { server.listen }

    begin
      strategy = Devise::OmniAuth::GitHub.new("appid", "secret", scope: "user")
      base = "http://#{address}"
      strategy.site = base
      strategy.authorize_url = "#{base}/login/oauth/authorize"
      strategy.token_url = "#{base}/login/oauth/access_token"

      redirect = "http://localhost:3000/users/auth/github/callback"
      url = strategy.authorize_url(redirect)
      q = URI::Params.parse(URI.parse(url).query.not_nil!)
      q["response_type"].should eq("code")
      q["scope"].should eq("user")

      auth = strategy.authenticate("wire-code", redirect)
      auth.provider.should eq("github")
      auth.uid.should eq("999")
      auth.info.nickname.should eq("wireuser")
      auth.info.email.should eq("wire@wire.dev") # primary+verified from /user/emails
      auth.info.name.should eq("Wire User")
      auth.info.urls["GitHub"].should eq("https://github.com/wireuser")
      auth.credentials.not_nil!.token.should eq("ghu.wire")
      auth.credentials.not_nil!.expires.should be_false
      auth.extra.not_nil!.all_emails.not_nil!.size.should eq(1)
      auth.extra.not_nil!.scope.not_nil!.as_s.should eq("user")
      auth.valid?.should be_true
    ensure
      server.close
    end
  end
end
