# HTTP-layer oracle spec (Phase H): the Crystal port reproduces
# oracle/http_expected.yml (captured from devise 4.9.4 inside the
# throwaway Rails 8.1.4 app tmp/http_app — see oracle/http_cases.rb).
#
# Same case IDs; values verbatim EXCEPT the mechanical scope
# substitution user→http_user (the model-level oracle spec already
# defines a top-level `User`, and Crystal compiles the whole spec/
# dir into one program — two `User` classes cannot coexist). The
# substitution touches exactly: route paths /users→/http_users, route
# prefixes user_→http_user_, the warden session key and the remember
# cookie name. Statuses, flash strings, Locations and DB effects are
# compared byte-for-byte.
#
# Rails-internal session keys (session_id/flash) have no port analog
# (cookie-session jar): http_register_session_keys and
# http_signin_session_keys assert the warden key's presence/absence.

require "spec"
require "http"
require "../src/devise_cr"

HTTP_EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/http_expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

# user → http_user (see header).
def deuser(s : String) : String
  s.gsub("/users", "/http_users").gsub("user_", "http_user_")
end

HTTP_TEST_URL = ENV["DEVISE_TEST_URL"]? ||
                "postgres://root@/crails_as_test?host=/var/run/postgresql"

ActiveRecord::Base.establish_connection(HTTP_TEST_URL)
ActiveRecord::Base.connection.exec(<<-SQL)
  CREATE TABLE IF NOT EXISTS http_users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR,
    encrypted_password VARCHAR,
    reset_password_token VARCHAR,
    reset_password_sent_at TIMESTAMP,
    remember_created_at TIMESTAMP,
    confirmation_token VARCHAR,
    confirmed_at TIMESTAMP,
    confirmation_sent_at TIMESTAMP,
    unconfirmed_email VARCHAR,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    unlock_token VARCHAR,
    locked_at TIMESTAMP,
    sign_in_count INTEGER NOT NULL DEFAULT 0,
    current_sign_in_at TIMESTAMP,
    last_sign_in_at TIMESTAMP,
    current_sign_in_ip VARCHAR,
    last_sign_in_ip VARCHAR,
    provider VARCHAR,
    uid VARCHAR,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP
  )
SQL
ActiveRecord::Base.connection.exec("DELETE FROM http_users")

ActionController.cookies_secret_key_base = "http-oracle-secret-key-base"
Devise.default_scope = "http_user"
Devise.mailer_sender = "test@example.com"
Devise.secret_key = "oracle-secret"

# Raw devise tokens are captured here (the gem oracle reads them from
# the test mailer; send_devise_notification override = HTTP_SENT pattern of
# oracle_spec.cr).
HTTP_SENT = [] of Tuple(Symbol, String)

class HttpUser < ActiveRecord::Base
  devise :database_authenticatable, :registerable, :recoverable,
         :rememberable, :validatable, :confirmable, :lockable,
         :timeoutable, :trackable, :omniauthable,
         omniauth_providers: [:google_oauth2]

  def send_devise_notification(notification : Symbol, *args) : Nil
    HTTP_SENT << {notification, args.first.to_s}
  end
end

# Guarded controller for the authenticate_user! cases (PrivateController
# of the gem app).
class PrivateHttpController < ActionController::Base
  before_action :authenticate_user!

  def show
    render plain: "secret"
  end
end

# --- harness -----------------------------------------------------------

class ControllerBox
  property controller : ActionController::Base?
  property io : IO::Memory = IO::Memory.new
end

LAST = ControllerBox.new

private def build_context(method : String, path : String,
                          body : String? = nil, content_type : String? = nil,
                          cookie : String? = nil) : HTTP::Server::Context
  headers = HTTP::Headers.new
  headers["Content-Type"] = content_type if content_type
  headers["Cookie"] = cookie if cookie
  request = HTTP::Request.new(method, path, headers, body)
  io = IO::Memory.new
  response = HTTP::Server::Response.new(io)
  LAST.io = io
  HTTP::Server::Context.new(request, response)
end

private def req(klass, action : String, method : String, path : String,
                body : String? = nil, cookie : String? = nil,
                route_params : Hash(String, String) = {} of String => String)
  content_type = body && body.includes?('=') && !body.starts_with?('{') ?
                 "application/x-www-form-urlencoded" : nil
  context = build_context(method, path, body, content_type, cookie)
  controller = klass.new(context)
  controller.__set_params(route_params)
  controller.__run_action(action)
  context.response.close
  LAST.controller = controller
  context
end

# "name=value; path=/" pairs of one response → request Cookie header.
private def cookie_header(context : HTTP::Server::Context, keep : Array(String)) : String?
  values = context.response.headers.get?("Set-Cookie") || [] of String
  pairs = values.map { |v| v.split(';').first }.select { |p|
    keep.any? { |k| p.starts_with?("#{k}=") }
  }
  pairs.empty? ? nil : pairs.join("; ")
end

private def status(context) : Int32
  context.response.status_code
end

private def location(context) : String
  context.response.headers["Location"]?.to_s
end

private def set_cookie(context) : String
  (context.response.headers.get?("Set-Cookie") || [] of String).join("\n")
end

def exp(id) : String
  deuser(HTTP_EXPECTED[id])
end

def flash_value(key : String, context : HTTP::Server::Context) : String?
  raw = set_cookie(context).split("\n")
    .find(&.starts_with?("crails_flash=")).try { |c| c.split(";").first }
  return nil unless raw
  replay = build_context("GET", "/", nil, nil, raw)
  ActionController::Flash.new(ActionController::Cookies.new(replay))[key]?
end

# Flash, как его видит СЛЕДУЮЩИЙ запрос: проигрываем flash-cookie из
# ответа в новый контекст (семантика read-once flash как в оракуле).
def next_flash(context : HTTP::Server::Context) : String?
  raw = set_cookie(context).split("\n")
    .find(&.starts_with?("crails_flash=")).try { |c| c.split(";").first } ||
       return nil
  replay = build_context("GET", "/", nil, nil, raw)
  ActionController::Flash.new(ActionController::Cookies.new(replay))["notice"]? ||
    ActionController::Flash.new(ActionController::Cookies.new(replay))["alert"]?
end

# --- route table --------------------------------------------------------

describe "devise routes" do
  it "mirrors the devise_for :users table" do
    set = CRails::Routes::RouteSet.new
    set.draw do
      devise_for :http_users
    end

    # devise routes only (the gem table also lists app routes: private,
    # rails/info, root). GET|POST shared-name lines expand to two.
    expected_lines = HTTP_EXPECTED.keys.select { |k| k.starts_with?("http_route_") }
      .map { |k| deuser(HTTP_EXPECTED[k]) }
      .select { |l| l.includes?("|devise/") }
    expected_targets = expected_lines.flat_map { |l|
      parts = l.split("|")
      if parts[1] == "GET" && parts[2] == "POST"
        ["GET|" + parts[3..].join("|"), "POST|" + parts[3..].join("|")]
      else
        [parts[1] + "|" + parts[2..].join("|")]
      end
    }.sort
    expected_names = expected_lines.map { |l| l.split("|").first }
      .reject(&.empty?).sort

    actual_targets = set.routes.map { |r| "#{r.verb}|#{r.pattern}|#{r.controller}##{r.action}" }.sort
    actual_names = set.routes.map(&.name).compact_map(&.to_s).reject(&.empty?).sort

    actual_targets.should eq expected_targets
    actual_names.should eq expected_names
  end
end

# --- registration / session flow ----------------------------------------

describe "devise sessions http flow" do
  it "registers without signing in when confirmable" do
    HTTP_SENT.clear
    context = req(Devise::RegistrationsController, "create", "POST", "/http_users",
      "user[email]=u@example.com&user[password]=secret123&user[password_confirmation]=secret123")
    status(context).should eq exp("http_register_status").to_i
    location(context).should eq exp("http_register_location")
    flash_value("notice", context).should eq exp("http_register_flash").split("=", 2)[1]?
    user = HttpUser.first.not_nil!
    # signs_in_automatically: no warden key in the fresh session
    LAST.controller.not_nil!.session["warden.user.http_user.key"]?.should be_nil
    HTTP_SENT.last[0].should eq :confirmation_instructions
  end

  it "signs out with flash" do
    HttpUser.first.not_nil!.tap do |u|
      u.assign_attributes({"confirmed_at" => Time.utc})
      u.save(validate: false)
    end
    signin = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123")
    cookie = cookie_header(signin, ["crails_session"]).not_nil!

    context = req(Devise::SessionsController, "destroy", "DELETE", "/http_users/sign_out",
      nil, cookie)
    status(context).should eq exp("http_signout_status").to_i
    flash_value("notice", context).should eq exp("http_signout_flash").split("=", 2)[1]?
  end

  it "renders the sign-in form" do
    context = req(Devise::SessionsController, "new", "GET", "/http_users/sign_in")
    status(context).should eq exp("http_signin_form_status").to_i
  end

  it "rejects a wrong password with 422 + alert" do
    context = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=wrong")
    status(context).should eq exp("http_signin_bad_status").to_i
    # wrong password: alert via flash.now (rendered in the same response)
    LAST.controller.not_nil!.flash["alert"].should eq(
      exp("http_signin_bad_flash").split(",").find(&.starts_with?("alert=")).not_nil!.split("=", 2)[1])
  end

  it "signs in: 303 to /, warden key [[id],salt]" do
    context = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123")
    status(context).should eq exp("http_signin_status").to_i
    location(context).should eq exp("http_signin_location")
    flash_value("notice", context).should eq exp("http_signin_flash").split("=", 2)[1]?

    controller = LAST.controller.not_nil!
    raw = controller.session["warden.user.http_user.key"].not_nil!
    payload = JSON.parse(raw).as_a
    payload[0].as_a[0].to_s.should eq HttpUser.first.not_nil!.id.to_s
    # Ruby-имена классов: Integer для любых int (oracle печатает Integer)
    format = payload.map { |p|
      r = p.raw
      if r.is_a?(Array)
        "[#{r.map { |e| e.raw.is_a?(Int64) ? "Integer" : e.raw.class.to_s }.join(",")}]"
      else
        r.is_a?(Int64) ? "Integer" : r.class.to_s
      end
    }.join("+")
    format.should eq exp("http_warden_key_format")
  end

  it "redirects a signed-in user away from the sign-in form" do
    signin = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123")
    cookie = cookie_header(signin, ["crails_session"]).not_nil!

    context = req(Devise::SessionsController, "new", "GET", "/http_users/sign_in",
      nil, cookie)
    status(context).should eq exp("http_signin_form_signed_in_status").to_i
    location(context).should eq exp("http_signin_form_signed_in_location")
  end
end

describe "devise authenticate_user!" do
  it "redirects anonymous to sign_in with alert (failure app)" do
    context = req(PrivateHttpController, "show", "GET", "/private")
    status(context).should eq exp("http_guard_unauth_status").to_i
    location(context).should eq exp("http_guard_unauth_location")
    flash_value("alert", context).should eq exp("http_guard_unauth_flash").split("=", 2)[1]
  end

  it "lets a signed-in user through" do
    signin = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123")
    cookie = cookie_header(signin, ["crails_session"]).not_nil!

    context = req(PrivateHttpController, "show", "GET", "/private", nil, cookie)
    status(context).should eq exp("http_guard_auth_status").to_i
    LAST.io.to_s.should contain(exp("http_guard_auth_body"))
  end
end

describe "devise rememberable" do
  it "sets remember_<scope>_token cookie" do
    context = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123&user[remember_me]=1")
    set_cookie(context).should contain("remember_http_user_token=")
  end

  it "auto-signs-in from the remember cookie alone" do
    signin = req(Devise::SessionsController, "create", "POST", "/http_users/sign_in",
      "user[email]=u@example.com&user[password]=secret123&user[remember_me]=1")
    remember = cookie_header(signin, ["remember_http_user_token"]).not_nil!

    context = req(PrivateHttpController, "show", "GET", "/private", nil, remember)
    status(context).should eq exp("http_remember_auto_sign_in_status").to_i
  end
end

describe "devise passwords" do
  it "requests reset instructions" do
    HTTP_SENT.clear
    context = req(Devise::PasswordsController, "create", "POST", "/http_users/password",
      "user[email]=u@example.com")
    status(context).should eq exp("http_pw_request_status").to_i
    location(context).should eq exp("http_pw_request_location")
    flash_value("notice", context).should eq exp("http_pw_request_flash").split("=", 2)[1]?
    HTTP_SENT.last[0].should eq :reset_password_instructions
    (HTTP_SENT.last[1].size > 0).should eq(exp("http_pw_token_present") == "true")
  end

  it "shows the edit form" do
    token = HTTP_SENT.last[1]
    context = req(Devise::PasswordsController, "edit", "GET",
      "/http_users/password/edit?reset_password_token=#{token}")
    status(context).should eq exp("http_pw_edit_status").to_i
  end

  it "resets the password and signs in" do
    token = HTTP_SENT.last[1]
    context = req(Devise::PasswordsController, "update", "PATCH", "/http_users/password",
      "user[reset_password_token]=#{token}&user[password]=newpass123&user[password_confirmation]=newpass123")
    status(context).should eq exp("http_pw_update_status").to_i
    location(context).should eq exp("http_pw_update_location")
    flash_value("notice", context).should eq exp("http_pw_update_flash").split("=", 2)[1]?
    (HttpUser.first.not_nil!.valid_password?("newpass123")).to_s.should eq exp("http_pw_new_password_works")
  end
end

describe "devise confirmations" do
  it "confirms by the raw token" do
    HTTP_SENT.clear
    user = HttpUser.first.not_nil!
    user.assign_attributes({"confirmed_at" => nil})
    user.save(validate: false)
    user.send_confirmation_instructions

    context = req(Devise::ConfirmationsController, "show", "GET",
      "/http_users/confirmation?confirmation_token=#{HTTP_SENT.last[1]}")
    status(context).should eq exp("http_confirm_status").to_i
    location(context).should eq exp("http_confirm_location")
    flash_value("notice", context).should eq exp("http_confirm_flash").split("=", 2)[1]?
    (!HttpUser.first.not_nil!.attributes["confirmed_at"]?.nil?).to_s.should eq exp("http_confirm_confirmed")
  end
end

describe "devise omniauth" do
  it "returns 404 passthru for unconfigured provider" do
    context = req(Devise::OmniauthCallbacksController, "passthru", "GET",
      "/http_users/auth/google_oauth2", nil, nil,
      {"provider" => "google_oauth2"})
    status(context).should eq exp("http_omniauth_passthru_status").to_i
  end
end
