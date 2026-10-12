# Unit specs for the Warden replacement (Session) and the JWT module.
# Oracle cases live in oracle_spec.cr; these cover the contract pieces
# the oracle harness does not exercise (flash strings, session store,
# JWT roundtrip/tamper/expiry, refresh rotation, ruby-jwt cross-decode).

require "spec"
require "../src/devise_cr"

SESSIONS_TEST_URL = ENV["DEVISE_TEST_URL"]? ||
                    "postgres://root@/crails_as_test?host=/var/run/postgresql"

ActiveRecord::Base.establish_connection(SESSIONS_TEST_URL)
# NOTE: no full `DELETE FROM users` here — spec files run alphabetically, and
# this one loads after oracle_spec.cr whose top-level fixtures must survive.
ActiveRecord::Base.connection.exec("DELETE FROM users WHERE email LIKE 'sess%'")
ActiveRecord::Base.connection.exec("DELETE FROM devise_refresh_tokens")

class SessionUser < ActiveRecord::Base
  set_table_name "users"
  devise :database_authenticatable, :validatable
end

SESSION_USER = SessionUser.create!({"email" => "sess@e.co", "password" => "secret123",
                                    "password_confirmation" => "secret123"})

CROSS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." \
              "eyJzdWIiOiI0MiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNjAwMDAwMDAwfQ." \
              "LIPKpx7aLlbbSh2TUzJBW1zYUSR--hgNrECgETd1R8Q"

describe Devise::Session do
  it "sign_in stores scope, sets flash notice" do
    session = Devise::Session.new
    session.signed_in?("user").should be_false
    session.sign_in(SESSION_USER)
    session.signed_in?("user").should be_true
    session.flash["notice"].should eq("Signed in successfully.")
    session.current_user(SessionUser).try(&.id).should eq(SESSION_USER.id)
  end

  it "sign_out clears scope, sets flash notice" do
    session = Devise::Session.new
    session.sign_in(SESSION_USER)
    session.sign_out
    session.signed_in?("user").should be_false
    session.current_user(SessionUser).should be_nil
    session.flash["notice"].should eq("Signed out successfully.")
  end

  it "authenticate returns the user when signed in" do
    session = Devise::Session.new
    session.sign_in(SESSION_USER)
    called = false
    result = session.authenticate(SessionUser) { called = true }
    called.should be_false
    result.try(&.id).should eq(SESSION_USER.id)
  end

  it "authenticate yields and flashes alert when not signed in" do
    session = Devise::Session.new
    called = false
    result = session.authenticate(SessionUser) { called = true }
    called.should be_true
    result.should be_nil
    session.flash["alert"].should eq("You need to sign in or sign up before continuing.")
  end
end

describe Devise::JWT do
  after_each do
    ActiveRecord::Base.connection.exec("DELETE FROM devise_refresh_tokens")
  end

  it "roundtrips an access token" do
    Devise::JWT.secret = "spec-secret"
    token = Devise::JWT.issue_access(42_i64)
    payload = Devise::JWT.decode(token)
    payload["sub"].as_s.should eq("42")
    payload["iat"].as_i.should be > 0
    payload["exp"].as_i.should be > payload["iat"].as_i
  end

  it "rejects a tampered signature" do
    Devise::JWT.secret = "spec-secret"
    token = Devise::JWT.issue_access(42_i64)
    header, body, _ = token.split('.')
    expect_raises(Devise::JWT::TokenInvalid) do
      Devise::JWT.decode("#{header}.#{body}.#{token.split('.')[2].reverse}")
    end
  end

  it "rejects a wrong secret" do
    Devise::JWT.secret = "spec-secret"
    token = Devise::JWT.issue_access(42_i64)
    Devise::JWT.secret = "other-secret"
    expect_raises(Devise::JWT::TokenInvalid) { Devise::JWT.decode(token) }
  end

  it "rejects an expired token" do
    Devise::JWT.secret = "spec-secret"
    # assembled by hand: exp is well in the past
    token = Devise::JWT.encode({
      "sub" => "42",
      "iat" => 1_600_000_000_i64,
      "exp" => 1_600_000_060_i64,
    } of String => JSON::Any | String | Int64 | Float64 | Nil)
    expect_raises(Devise::JWT::TokenExpired) { Devise::JWT.decode(token) }
  end

  it "decodes a ruby-jwt (HS256) token with the same secret" do
    Devise::JWT.secret = "cross-secret"
    payload = Devise::JWT.decode(CROSS_TOKEN)
    payload["sub"].as_s.should eq("42")
    payload["exp"].as_i64.should eq(4_102_444_800_i64)
  end

  it "issue_pair + refresh rotate and revoke" do
    Devise::JWT.secret = "spec-secret"
    pair = Devise::JWT.issue_pair(SESSION_USER.id.not_nil!)
    Devise::JWT.decode(pair[:access])["sub"].as_s.should eq(SESSION_USER.id.to_s)

    rotated = Devise::JWT.refresh(pair[:refresh])
    rotated[:user_id].should eq(SESSION_USER.id)
    Devise::JWT.decode(rotated[:access])["sub"].as_s.should eq(SESSION_USER.id.to_s)

    # replaying the consumed token must fail
    expect_raises(Devise::JWT::TokenInvalid) { Devise::JWT.refresh(pair[:refresh]) }
  end

  it "refresh rejects an unknown token" do
    Devise::JWT.secret = "spec-secret"
    expect_raises(Devise::JWT::TokenInvalid) { Devise::JWT.refresh("f" * 64) }
  end
end
