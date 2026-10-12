# Test-helpers oracle spec: the Crystal port reproduces
# oracle/test_helpers_expected.yml (captured from devise 4.9.4 +
# warden 1.2.9 in tmp/http_app — see oracle/test_helpers_cases.rb).
#
# The gem's helpers delegate to Warden::Test::Helpers (login_as/logout on
# the next request); the port writes/deletes the warden session key on a
# controller's cookie-session — the Set-Cookie of that controller plays
# the role of the integration session's cookie jar, and is replayed into
# the next request (harness below, same shape as http_oracle_spec.cr).
#
# Scope: th_user (a dedicated model on its own th_users table) so this
# spec does not depend on Devise.default_scope set by http_oracle_spec.cr
# nor share fixtures with it (spec files compile in readdir order — this
# file may run before http_oracle_spec.cr); th_signout_key_present keeps
# the oracle's inverted name (true = the warden key is GONE after
# sign_out).

require "spec"
require "http"
require "../src/devise_cr"

TH_EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/test_helpers_expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

TH_TEST_URL = ENV["DEVISE_TEST_URL"]? ||
              "postgres://root@/crails_as_test?host=/var/run/postgresql"

# user → th_user (same mechanical scope substitution as http_oracle_spec).
def th_deuser(s : String) : String
  s.gsub("user", "th_user")
end

ActiveRecord::Base.establish_connection(TH_TEST_URL)

# Собственная таблица (не http_users!): Dir.glob компилирует spec-файлы
# в readdir-порядке, этот спек может выполниться ДО http_oracle_spec, и
# общая таблица ломала бы его фикстуры.
ActiveRecord::Base.connection.exec(<<-SQL)
  CREATE TABLE IF NOT EXISTS th_users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR,
    encrypted_password VARCHAR,
    remember_created_at TIMESTAMP,
    confirmed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP
  )
SQL
ActiveRecord::Base.connection.exec("DELETE FROM th_users")

ActionController.cookies_secret_key_base = "test-helpers-secret-key-base"

class ThUser < ActiveRecord::Base
  set_table_name "th_users"
  devise :database_authenticatable, :rememberable, :validatable
end

# Guarded pages for the th_user scope (PrivateController + the
# require_no_authentication redirect of the gem app).
class ThPrivateController < ActionController::Base
  before_action :guard_th

  def show
    render plain: "secret"
  end

  # require_no_authentication analog: signed-in requests are redirected
  # away (302 to after_sign_in_path_for → "/").
  def signin_page
    redirect_to("/", 302)
  end

  private def guard_th : Nil
    redirect_to("/th_users/sign_in", 302) if Devise.current(self, "th_user").nil?
  end
end

# --- harness (same shape as http_oracle_spec.cr) -------------------------

private def th_build_context(method : String, path : String,
                             cookie : String? = nil) : HTTP::Server::Context
  headers = HTTP::Headers.new
  headers["Cookie"] = cookie if cookie
  request = HTTP::Request.new(method, path, headers)
  io = IO::Memory.new
  ThBox.io = io
  response = HTTP::Server::Response.new(io)
  HTTP::Server::Context.new(request, response)
end

class ThBox
  class_property io : IO::Memory? = nil
end

private def th_last_body : String
  io = ThBox.io.not_nil!
  io.rewind
  io.gets_to_end.split("\r\n\r\n", 2)[1]?.to_s
end

private def th_req(action : String, cookie : String? = nil) : HTTP::Server::Context
  context = th_build_context("GET", "/th-private", cookie)
  controller = ThPrivateController.new(context)
  controller.__set_params({"id" => "1"} of String => String)
  controller.__run_action(action)
  context.response.close
  context
end

private def th_status(context) : Int32
  context.response.status_code
end

private def th_location(context) : String
  context.response.headers["Location"]?.to_s
end

# The "integration session": a controller whose session writes persist
# into a Set-Cookie replayable by the next request.
private def th_session_controller : ActionController::Base
  context = th_build_context("GET", "/th-session")
  ThPrivateController.new(context)
end

private def th_cookie(controller : ActionController::Base) : String?
  values = controller.context.response.headers.get?("Set-Cookie") || [] of String
  pairs = values.map { |v| v.split(';').first }.select(&.starts_with?("crails_session="))
  pairs.empty? ? nil : pairs.join("; ")
end

# The test class including the helpers (provides `controller`).
class ThHelpers
  include Devise::Test::IntegrationHelpers

  property controller : ActionController::Base

  def initialize(@controller)
  end
end

# --- cases ---------------------------------------------------------------

describe "devise test helpers oracle" do
  it "mirrors test_helpers_expected.yml" do
    # id pinned to 1 (oracle: sqlite-sequence reset; th_warden_key_id)
    ActiveRecord::Base.connection.exec("DELETE FROM th_users")
    ActiveRecord::Base.connection.exec(
      "SELECT setval('th_users_id_seq', 1, false)")
    user = ThUser.new(for_load: false)
    user.email = "th@example.com"
    user.password = "secret123"
    user.assign_attributes({"confirmed_at" => Time.utc} of String => ActiveRecord::Value)
    user.save!
    th = ThHelpers.new(th_session_controller)

    # --- find_scope ---
    Devise.find_scope(user).should eq th_deuser(TH_EXPECTED["th_find_scope_class"])

    # --- sign_in via helper ---
    th.sign_in(user)
    cookie = th_cookie(th.controller).not_nil!
    th.controller.session["warden.user.th_user.key"]?.should_not be_nil

    context = th_req("show", cookie)
    th_status(context).should eq TH_EXPECTED["th_signed_in_private_status"].to_i
    th_last_body.strip.should eq TH_EXPECTED["th_signed_in_private_body"]

    raw = th.controller.session["warden.user.th_user.key"].not_nil!
    payload = JSON.parse(raw).as_a
    # Ruby prints Integer; the port's JSON ids are Int64
    format = payload.map { |part|
      part.as_a? ? "[#{part.as_a.map { |v| v.raw.is_a?(Int64) ? "Integer" : v.raw.class.to_s }.join(",")}]" : part.raw.class.to_s
    }.join("+")
    format.should eq TH_EXPECTED["th_warden_key_format"]
    payload[0].as_a[0].to_s.should eq TH_EXPECTED["th_warden_key_id"]
    payload[0].as_a[0].to_s.should eq user.id.to_s

    # require_no_authentication now redirects (already signed in)
    context = th_req("signin_page", cookie)
    th_status(context).should eq TH_EXPECTED["th_signed_in_signin_status"].to_i
    th_location(context).should eq TH_EXPECTED["th_signed_in_signin_location"]

    # explicit scope: same session key
    th2 = ThHelpers.new(th_session_controller)
    th2.sign_in(user, scope: "th_user")
    cookie2 = th_cookie(th2.controller).not_nil!
    th_status(th_req("show", cookie2)).should eq TH_EXPECTED["th_scope_explicit_private_status"].to_i

    # --- sign_out via helper ---
    th.sign_out("th_user")
    th.controller.session["warden.user.th_user.key"]?.should be_nil
    signed_out_cookie = th_cookie(th.controller).not_nil!
    context = th_req("show", signed_out_cookie)
    th_status(context).should eq TH_EXPECTED["th_signout_private_status"].to_i
    th_location(context).should eq th_deuser(TH_EXPECTED["th_signout_private_location"])

    replay = th_build_context("GET", "/", signed_out_cookie)
    ActionController::Session.new(ActionController::Cookies.new(replay))["warden.user.th_user.key"]?
      .nil?.should eq TH_EXPECTED["th_signout_key_present"] == "true"

    # sign_out accepts the resource too
    th3 = ThHelpers.new(th_session_controller)
    th3.sign_in(user)
    th3.sign_out(user)
    th3.controller.session["warden.user.th_user.key"]?.should be_nil
    th_status(th_req("show", th_cookie(th3.controller).not_nil!))
      .should eq TH_EXPECTED["th_signout_via_resource_status"].to_i
  end
end
