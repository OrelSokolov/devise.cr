# Oracle cases for Devise omniauthable (P2): the model side
# (`devise :omniauthable`, `omniauth_providers`, `Devise.friendly_token`,
# the canonical `from_omniauth` generator idiom) plus the
# omniauth-google-oauth2 1.1.1 strategy contract (scope normalization,
# authorize params/URL, AuthHash schema). Deterministic: network calls
# (token exchange, userinfo) are faked via singleton stubs, exactly the
# way the upstream strategy specs stub them.
#
# Run against the ORIGINAL gems:
#   ruby oracle/omniauth_cases.rb > oracle/omniauth_expected.yml
#
# Mirrored 1:1 in spec/omniauth_spec.cr. Line protocol: "<id>\t<value>".
#
# Two incompatible rack worlds: actionpack 8.1.4 (devise's oracle stack)
# needs rack >= 3, oauth2 2.0.8 needs rack < 3. The bare run splits into
# child processes and concatenates the output.

def render(v)
  s = v.is_a?(String) ? v : v.inspect
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

def case_run(id)
  puts "#{id}\t#{render(yield)}"
rescue StandardError => e
  puts "#{id}\traise:#{e.class.name}"
end

if ARGV.empty?
  [IO.popen([RbConfig.ruby, __FILE__, "model"]).read,
   IO.popen([RbConfig.ruby, __FILE__, "strategy"]).read,
   IO.popen([RbConfig.ruby, __FILE__, "github"]).read].each { |out| puts out }
  exit 0
end

# ===========================================================================
if ARGV.first == "model"
# ===========================================================================
gem "rack", "= 3.2.7" # omniauth 2.1.3 + rack-protection 4.2.1 + actionpack 8.1.4
gem "rack-protection", "= 4.2.1"
gem "devise", "= 4.9.4"
gem "activerecord", "= 8.1.4"
gem "activesupport", "= 8.1.4"
gem "bcrypt", "= 3.1.21"
gem "sqlite3", ">= 2.1"
gem "omniauth", "= 2.1.3"

require "devise"
require "devise/orm/active_record"

ActiveRecord::Migration.verbose = false
ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.define do
  create_table :oauth_users do |t|
    t.string   :provider,           null: true
    t.string   :uid,                null: true
    t.string   :email
    t.string   :encrypted_password, null: false, default: ""
    t.string   :name
    t.string   :image
    t.datetime :remember_created_at
    t.timestamps
  end
end

class OauthUser < ActiveRecord::Base
  self.table_name = "oauth_users"
  devise :database_authenticatable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: %i[google_oauth2]

  # Canonical devise-wiki / generated-app idiom (first_or_create is the
  # same call find_or_create_by makes; the bare block form of the latter
  # no longer accepts zero arguments on AR 8.1).
  def self.from_omniauth(auth)
    where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
      user.email = auth.info.email
      user.password = Devise.friendly_token[0, 20]
      user.name = auth.info.name
      user.image = auth.info.image
    end
  end
end

# omniauthable without omniauth_providers → default []
class PlainOauthUser < ActiveRecord::Base
  self.table_name = "oauth_users"
  devise :omniauthable
end

AUTH = OmniAuth::AuthHash.new(
  provider: "google_oauth2",
  uid: "1000000000000000001",
  info: { name: "Test User", email: "test@example.com",
          image: "https://lh3.googleusercontent.com/a-/photo.jpg" }
)

# --- modules / providers ---------------------------------------------------
case_run("oa_modules")           { OauthUser.devise_modules.include?(:omniauthable) }
case_run("oa_providers")         { OauthUser.omniauth_providers }
case_run("oa_providers_default") { PlainOauthUser.omniauth_providers }

# --- Devise.friendly_token -------------------------------------------------
case_run("oa_friendly_token_shape") do
  t = Devise.friendly_token
  [t.length == 20, t.match?(/\A[A-Za-z0-9_-]+\z/), t.count("lIO0").zero?]
end
case_run("oa_friendly_token_len") { Devise.friendly_token(32).length == 32 }

# --- from_omniauth (generated idiom) ----------------------------------------
case_run("oa_from_create") do
  u = OauthUser.from_omniauth(AUTH)
  [u.persisted?, u.provider, u.uid, u.email, u.name,
   u.encrypted_password.match?(/\A\$2a\$12\$[\.\/A-Za-z0-9]{53}\z/)]
end
case_run("oa_from_idempotent") do
  a, b = OauthUser.from_omniauth(AUTH), OauthUser.from_omniauth(AUTH)
  [a.id == b.id, OauthUser.count == 1]
end
case_run("oa_from_new_uid") do
  other = OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "42",
                                 info: { email: "other@example.com" })
  u = OauthUser.from_omniauth(other)
  [u.persisted?, u.uid, OauthUser.count == 2]
end
case_run("oa_oauth_user_valid") do
  u = OauthUser.from_omniauth(AUTH)
  u.name = "Renamed"
  [u.valid?, u.errors.empty?]
end

# --- OmniAuth::AuthHash schema ----------------------------------------------
case_run("oa_auth_hash_valid") do
  OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1",
                         info: { name: "X", email: "x@e.co" }).valid?
end
case_run("oa_auth_hash_invalid_no_name") do
  OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1",
                         info: { email: "x@e.co" }).valid? # email → InfoHash#name fallback
end
case_run("oa_auth_hash_invalid_empty_info") do
  OmniAuth::AuthHash.new(provider: "google_oauth2", uid: "1", info: {}).valid?
end
case_run("oa_auth_hash_name_fallback") do
  [
    OmniAuth::AuthHash.new(info: { first_name: "A", last_name: "B" }).info.name,
    OmniAuth::AuthHash.new(info: { nickname: "nick" }).info.name,
    OmniAuth::AuthHash.new(info: { email: "e@x.co" }).info.name,
    OmniAuth::AuthHash.new(info: {}).info.name
  ]
end

# ===========================================================================
elsif ARGV.first == "github"
# ===========================================================================
gem "rack", "= 2.2.17" # same oauth2 2.0.8 world as the strategy branch
gem "rack-protection", "= 2.1.0"
gem "omniauth", "= 2.1.3"
gem "oauth2", "= 2.0.8"
# omniauth-github 2.0.1 from unpacked sources, on top of the vendored
# omniauth-oauth2 1.8.0 (runtime surface compatible with oauth2 2.0.8).
%w[
  oracle/vendor/omniauth-oauth2-1.8.0/lib
  oracle/vendor/omniauth-github-2.0.1/lib
].each { |p| $LOAD_PATH.unshift(p) unless $LOAD_PATH.include?(p) }
require "json"
require "omniauth-github"

def sorted(obj)
  case obj
  when Hash
    obj.keys.map(&:to_s).sort.each_with_object({}) { |k, h| h[k] = sorted(obj[k]) }
  when Array then obj.map { |v| sorted(v) }
  else obj
  end
end

OmniAuth.config.test_mode = true

def make_github(options = {})
  OmniAuth::Strategies::GitHub.new(nil, "appid", "secret", options).tap do |s|
    session = {}
    env = { "rack.session" => session }
    s.instance_variable_set(:@env, env)
    request = Struct.new(:params, :cookies, :env).new({}, {}, env)
    s.define_singleton_method(:request) { request }
    s.define_singleton_method(:mock_session) { session }
  end
end

case_run("gh_client_site")   { make_github.client.site }
case_run("gh_authorize_url") { make_github.client.options[:authorize_url] }
case_run("gh_token_url") do
  URI.join(make_github.client.site, make_github.client.options[:token_url]).to_s
end

case_run("gh_scope_default") { make_github.authorize_params[:scope] }
case_run("gh_scope_custom")  { make_github(scope: "user,public_repo").authorize_params[:scope] }
case_run("gh_state_in_session") do
  s = make_github
  state = s.authorize_params[:state]
  [state.match?(/\A[0-9a-f]{48}\z/) != nil, s.mock_session["omniauth.state"] == state]
end
case_run("gh_authorize_url_full") do
  s = make_github(scope: "user")
  url = s.client.auth_code.authorize_url(
    s.authorize_params.merge(redirect_uri: "http://localhost:3000/users/auth/github/callback"))
  URI.decode_www_form(URI(url).query)
    .reject { |k, _| k == "state" }
    .push(["state", /\A[0-9a-f]{48}\z/.match(URI.decode_www_form(URI(url).query).to_h["state"]) ? "hex48" : "bad"])
    .sort
end

# --- github AuthHash (faked token/user/emails) -------------------------------
GH_RAW_INFO = {
  "login" => "testuser",
  "id" => 38_758_392,
  "name" => "Test User",
  "avatar_url" => "https://avatars.githubusercontent.com/u/38758392?v=4",
  "html_url" => "https://github.com/testuser",
  "blog" => "https://blog.example.com",
  "email" => "public@example.com"
}
GH_EMAILS = [
  { "email" => "primary@example.com", "primary" => true,  "verified" => true },
  { "email" => "other@example.com",   "primary" => false, "verified" => true }
]

def gh_strategy(scope, emails)
  options = emails.empty? ? {} : { scope: scope }
  make_github(options).tap do |s|
    access_token = Struct.new(:token, :options).new("ghu.access.token", {})
    access_token.define_singleton_method(:[]) { |k| k.to_s == "scope" ? scope : nil }
    access_token.define_singleton_method(:expires?) { false }
    access_token.define_singleton_method(:get) do |url, _opts = {}|
      Struct.new(:parsed).new(url.to_s == "user/emails" ? emails : GH_RAW_INFO)
    end
    s.define_singleton_method(:access_token) { access_token }
  end
end

case_run("gh_hash_user") do
  JSON.generate(sorted(gh_strategy("user", GH_EMAILS).auth_hash.to_hash))
end
case_run("gh_hash_no_email_scope") do
  JSON.generate(sorted(gh_strategy(nil, []).auth_hash.to_hash))
end
case_run("gh_hash_uid") { gh_strategy("user", GH_EMAILS).auth_hash.uid }
case_run("gh_email_access") do
  gh_strategy("user", GH_EMAILS).tap { |s| s.instance_variable_set(:@raw_info, GH_RAW_INFO) }
  %w[user user:email repo].map do |sc|
    s = make_github(scope: sc)
    s.instance_variable_set(:@emails, [])
    s.send(:email_access_allowed?)
  end
end

# ===========================================================================
else # "strategy"
# ===========================================================================
gem "rack", "= 2.2.17" # oauth2 2.0.8 requires rack >= 1.2, < 3
gem "rack-protection", "= 2.1.0"
gem "omniauth", "= 2.1.3"
gem "oauth2", "= 2.0.8"
# omniauth-oauth2 1.8.0 + omniauth-google-oauth2 1.1.1 from unpacked
# sources (the local mirror no longer serves the oauth2 1.x they declare;
# the runtime surface used here is compatible with oauth2 2.0.8).
%w[
  oracle/vendor/omniauth-oauth2-1.8.0/lib
  oracle/vendor/omniauth-google-oauth2-1.1.1/lib
].each { |p| $LOAD_PATH.unshift(p) unless $LOAD_PATH.include?(p) }
require "json"
require "omniauth-google-oauth2"

# Recursively sort a Hash (and its nested values) so the JSON rendering
# is order-independent.
def sorted(obj)
  case obj
  when Hash
    obj.keys.map(&:to_s).sort.each_with_object({}) { |k, h| h[k] = sorted(obj[k]) }
  when Array then obj.map { |v| sorted(v) }
  else obj
  end
end

# Same harness shape as the upstream spec: stub #request with a double.
OmniAuth.config.test_mode = true

def make_strategy(options = {})
  OmniAuth::Strategies::GoogleOauth2.new(nil, "appid", "secret", options).tap do |s|
    session = {}
    env = { "rack.session" => session }
    s.instance_variable_set(:@env, env)
    request = Struct.new(:params, :cookies, :env).new({}, {}, env)
    s.define_singleton_method(:request) { request }
    s.define_singleton_method(:mock_session) { session }
  end
end

case_run("g_client_site")   { make_strategy.client.site }
case_run("g_authorize_url") { make_strategy.client.options[:authorize_url] }
case_run("g_token_url") do
  URI.join(make_strategy.client.site, make_strategy.client.options[:token_url]).to_s
end

case_run("g_scope_default") { make_strategy.authorize_params[:scope] }
case_run("g_scope_custom") do
  make_strategy(authorize_params: { scope: "profile,email,calendar" }).authorize_params[:scope]
end
case_run("g_scope_url_untouched") do
  make_strategy(authorize_params: { scope: "https://www.googleapis.com/auth/calendar.profile" })
    .authorize_params[:scope]
end
case_run("g_access_type_default") { make_strategy.authorize_params[:access_type] }
case_run("g_state_in_session") do
  s = make_strategy
  state = s.authorize_params[:state]
  [state.match?(/\A[0-9a-f]{48}\z/) != nil, s.mock_session["omniauth.state"] == state]
end
case_run("g_authorize_url_full") do
  s = make_strategy
  url = s.client.auth_code.authorize_url(
    s.authorize_params.merge(redirect_uri: "http://localhost:3000/users/auth/google_oauth2/callback"))
  # state is random per call — assert its shape separately, sort the rest
  URI.decode_www_form(URI(url).query)
    .reject { |k, _| k == "state" }
    .push(["state", /\A[0-9a-f]{48}\z/.match(URI.decode_www_form(URI(url).query).to_h["state"]) ? "hex48" : "bad"])
    .sort
end

# --- google_oauth2 AuthHash (faked token/userinfo) ---------------------------
RAW_INFO = {
  "sub" => "1000000000000000001",
  "name" => "Test User",
  "given_name" => "Test",
  "family_name" => "User",
  "picture" => "https://lh3.googleusercontent.com/a-/photo.jpg",
  "email" => "test@example.com",
  "email_verified" => true,
  "profile" => "https://plus.google.com/1000000000000000001"
}

def fake_response(parsed)
  Struct.new(:parsed).new(parsed)
end

def oauth_user_strategy(raw_info, token_info, id_token: nil)
  make_strategy(skip_jwt: true).tap do |s|
    access_token = Struct.new(:token, :refresh_token).new("ya29.access.token", nil)
    access_token.define_singleton_method(:[]) { |k| k.to_s == "id_token" ? id_token : nil }
    access_token.define_singleton_method(:expires?) { false }
    access_token.define_singleton_method(:get) { |_url| fake_response(raw_info) }
    s.define_singleton_method(:access_token) { access_token }
    s.define_singleton_method(:client) do
      client = Struct.new(:site).new("https://oauth2.googleapis.com")
      client.define_singleton_method(:request) { |_verb, _url, _opts = {}| fake_response(token_info) }
      client
    end
  end
end

case_run("g_hash_verified") do
  JSON.generate(sorted(oauth_user_strategy(RAW_INFO, { "scope" => "email profile", "aud" => "appid" }).auth_hash.to_hash))
end
case_run("g_hash_unverified_email") do
  raw = RAW_INFO.merge("email_verified" => false)
  JSON.generate(sorted(oauth_user_strategy(raw, { "scope" => "email profile" }).auth_hash.to_hash))
end
case_run("g_hash_no_name") do
  raw = { "sub" => "555", "email" => "noname@example.com", "email_verified" => true }
  JSON.generate(sorted(oauth_user_strategy(raw, { "scope" => "email profile" }).auth_hash.to_hash))
end
case_run("g_hash_uid_sub") { oauth_user_strategy(RAW_INFO, {}).auth_hash.uid }

end
