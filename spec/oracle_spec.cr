# Oracle spec: the Crystal port must reproduce oracle/expected.yml
# exactly (captured from devise 4.9.4 over SQLite in-memory). Same case
# IDs, no edits; values use the same \n/\t escape protocol.

require "spec"
require "crypto/bcrypt"
require "../src/devise_cr"

EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

def escape(s : String | Bool) : String
  s = s.to_s
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

TEST_URL = ENV["DEVISE_TEST_URL"]? ||
           "postgres://root@/crails_as_test?host=/var/run/postgresql"

ActiveRecord::Base.establish_connection(TEST_URL)
ActiveRecord::Base.connection.exec("DELETE FROM users")
ActiveRecord::Base.connection.exec("DELETE FROM members")

Devise.mailer_sender = "test@example.com"
Devise.secret_key = "oracle-secret"

class User < ActiveRecord::Base
  devise :database_authenticatable, :rememberable, :validatable
end

# P1 model: all P1 modules; notification dispatch is recorded to SENT
# (the model-side oracle asserts dispatch, the real Devise::Mailer is
# exercised by the mail_* cases).
SENT = [] of Tuple(Symbol, String)

class Member < ActiveRecord::Base
  devise :database_authenticatable, :validatable, :recoverable,
         :confirmable, :trackable, :lockable, :timeoutable

  def send_devise_notification(notification : Symbol, *args) : Nil
    SENT << {notification, args.first.to_s}
  end
end

def member_create(email : String, password : String = "secret123") : Member
  Member.create!({"email" => email, "password" => password,
                  "password_confirmation" => password})
end

class PepperedUser < ActiveRecord::Base
  set_table_name "users"
  devise :database_authenticatable, :validatable
  self.pepper = "s3cr3t-pepper"
end

USER = User.create!({"email" => "a@b.c", "password" => "secret123",
                     "password_confirmation" => "secret123"})

CASES = {
  "pw_digest_shape" => -> { USER.encrypted_password.to_s.matches?(/^\$2a\$12\$[.\/A-Za-z0-9]{53}$/).to_s },
  "pw_valid"        => -> { User.find?(USER.id.not_nil!).not_nil!.valid_password?("secret123").to_s },
  "pw_wrong"        => -> { User.find?(USER.id.not_nil!).not_nil!.valid_password?("nope").to_s },
  "pw_blank_hash"   => -> { User.new({"email" => "x@y.z"}).valid_password?("any").to_s },
  "pw_deterministic_by_salt" => -> {
    ep = USER.encrypted_password.to_s
    salt22 = ep[7, 22]
    Crypto::Bcrypt.new("secret123", salt22, 12).to_s.starts_with?(ep[0, 29]).to_s
  },
  "pw_pepper_digest" => -> {
    u = PepperedUser.new
    u.password = "secret123"
    ep = u.encrypted_password.to_s
    Crypto::Bcrypt.new("secret123s3cr3t-pepper", ep[7, 22], 12).to_s == ep
  },
  "pw_pepper_valid" => -> {
    u = PepperedUser.create!({"email" => "p@q.r", "password" => "secret123",
                              "password_confirmation" => "secret123"})
    [u.valid_password?("secret123"), u.valid_password?("secret123s3cr3t-pepper")].inspect
  },
  # --- validatable ---
  "val_ok" => -> {
    u = User.new({"email" => "ok@e.co"})
    u.password = "longenough"
    u.password_confirmation = "longenough"
    u.valid?.to_s
  },
  "val_email_missing" => -> {
    u = User.new
    u.password = "longenough"
    u.password_confirmation = "longenough"
    [u.valid?, u.errors.group_by_attribute.has_key?("email")].inspect
  },
  "val_email_bad" => -> {
    u = User.new({"email" => "no-at"})
    u.password = "longenough"
    u.password_confirmation = "longenough"
    [u.valid?, u.errors.group_by_attribute.has_key?("email")].inspect
  },
  "val_email_uniq" => -> {
    u = User.new({"email" => USER.email.not_nil!.upcase})
    u.password = "longenough"
    u.password_confirmation = "longenough"
    [u.valid?, u.errors.group_by_attribute.has_key?("email")].inspect
  },
  "val_pw_short" => -> {
    u = User.new({"email" => "s@e.co"})
    u.password = "abc"
    u.password_confirmation = "abc"
    [u.valid?, u.errors.group_by_attribute.has_key?("password")].inspect
  },
  "val_pw_long" => -> {
    u = User.new({"email" => "s@e.co"})
    u.password = "x" * 129
    u.password_confirmation = "x" * 129
    [u.valid?, u.errors.group_by_attribute.has_key?("password")].inspect
  },
  "val_pw_mismatch" => -> {
    u = User.new({"email" => "s@e.co"})
    u.password = "longenough"
    u.password_confirmation = "different"
    [u.valid?, u.errors.group_by_attribute.has_key?("password_confirmation")].inspect
  },
  "val_update_no_pw" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.email = "new@e.co"
    u.valid?.to_s
  },
  # --- update_with_password ---
  "uwp_ok" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    res = u.update_with_password({"current_password" => "secret123", "email" => "uwp@e.co"})
    [res, User.find?(USER.id.not_nil!).not_nil!.email].inspect
  },
  "uwp_bad_pw" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    res = u.update_with_password({"current_password" => "WRONG", "email" => "hacked@e.co"})
    [res, u.errors.group_by_attribute.has_key?("current_password"),
     User.find?(USER.id.not_nil!).not_nil!.email].inspect
  },
  "uwp_new_password" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    res = u.update_with_password({"current_password" => "secret123",
                                  "password" => "newpass99", "password_confirmation" => "newpass99"})
    [res, User.find?(USER.id.not_nil!).not_nil!.valid_password?("newpass99")].inspect
  },
  # --- authenticatable_salt / rememberable ---
  "auth_salt_shape" => -> { USER.authenticatable_salt.not_nil!.matches?(/^\$2a\$12\$[.\/A-Za-z0-9]{22}$/).to_s },
  "rem_me" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    (!u.remember_created_at.nil?).to_s
  },
  "rem_serialize" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    key, token, generated_at = User.serialize_into_cookie(u)
    [key == [USER.id.not_nil!], token == u.authenticatable_salt,
     generated_at.matches?(/^\d+(\.\d+)?$/) != nil].inspect
  },
  "rem_from_cookie" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    User.serialize_from_cookie(*User.serialize_into_cookie(u)).try { |u| u.id == USER.id }.to_s
  },
  "rem_wrong_token" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    User.serialize_from_cookie([USER.id.not_nil!], "x" * 29, ("%f" % Time.utc.to_unix_f)).inspect
  },
  "rem_expired" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    old = ("%f" % (Time.utc - (Devise.remember_for + 1.second)).to_unix_f)
    User.serialize_from_cookie([USER.id.not_nil!], u.authenticatable_salt.not_nil!, old).inspect
  },
  "rem_forget" => -> {
    u = User.find?(USER.id.not_nil!).not_nil!
    u.remember_me!
    u.forget_me!
    User.find?(USER.id.not_nil!).not_nil!.remember_created_at.nil?.to_s
  },
  # --- registerable ---
  "reg_create" => -> {
    u = User.new({"email" => "reg@e.co"})
    u.password = "regpass1"
    u.password_confirmation = "regpass1"
    u.save
    [u.persisted?, u.valid_password?("regpass1")].inspect
  },

  # ===================================================================
  # P1: recoverable + confirmable + trackable + lockable + timeoutable
  # + Devise::Mailer headers (mirror of the P1 oracle section).
  # ===================================================================
  "tok_digest_fixed" => -> {
    Devise.token_generator.digest("reset_password_token", "raw-token-123").to_s
  },
  "tok_friendly_shape" => -> {
    t = Devise.friendly_token
    [t.size, t.matches?(/^[A-Za-z0-9_-]+$/), !t.matches?(/[lIO0]/)].inspect
  },
  # --- recoverable ---
  "rec_send_instructions" => -> {
    m = member_create("rec1@e.co")
    raw = m.send_reset_password_instructions
    db = Member.find?(m.id.not_nil!).not_nil!
    [raw.matches?(/^[A-Za-z0-9_-]{20}$/), db.reset_password_token.to_s.matches?(/^[0-9a-f]{64}$/),
     !db.reset_password_sent_at.nil?,
     SENT.last == {:reset_password_instructions, raw}].inspect
  },
  "rec_find_by_token" => -> {
    m = member_create("rec2@e.co")
    raw = m.send_reset_password_instructions
    [Member.with_reset_password_token(raw).try(&.id) == m.id,
     Member.with_reset_password_token("bogus-token-1234567").nil?].inspect
  },
  "rec_reset_by_token_ok" => -> {
    m = member_create("rec3@e.co")
    raw = m.send_reset_password_instructions
    r = Member.reset_password_by_token({"reset_password_token" => raw,
                                        "password" => "newpass99",
                                        "password_confirmation" => "newpass99"})
    [r.persisted?, Member.find?(m.id.not_nil!).not_nil!.valid_password?("newpass99"),
     Member.find?(m.id.not_nil!).not_nil!.reset_password_token.nil?].inspect
  },
  "rec_reset_by_token_invalid" => -> {
    r = Member.reset_password_by_token({"reset_password_token" => "no-such-token-1234",
                                        "password" => "newpass99",
                                        "password_confirmation" => "newpass99"})
    [r.persisted?, r.errors.group_by_attribute.has_key?("reset_password_token"),
     r.errors.details["reset_password_token"]?.try(&.map { |d| d[:error] })].inspect
  },
  "rec_reset_by_token_expired" => -> {
    m = member_create("rec4@e.co")
    raw = m.send_reset_password_instructions
    m.update_columns({"reset_password_sent_at" => Time.utc - 7.hours})
    r = Member.reset_password_by_token({"reset_password_token" => raw,
                                        "password" => "newpass99",
                                        "password_confirmation" => "newpass99"})
    [r.persisted?, r.errors.details["reset_password_token"]?.try(&.map { |d| d[:error] })].inspect
  },
  "rec_reset_blank_password" => -> {
    m = member_create("rec5@e.co")
    raw = m.send_reset_password_instructions
    r = Member.reset_password_by_token({"reset_password_token" => raw,
                                        "password" => "", "password_confirmation" => ""})
    [r.persisted?, r.errors.details["password"]?.try(&.map { |d| d[:error] })].inspect
  },
  "rec_reset_short_password" => -> {
    m = member_create("rec6@e.co")
    raw = m.send_reset_password_instructions
    r = Member.reset_password_by_token({"reset_password_token" => raw,
                                        "password" => "abc", "password_confirmation" => "abc"})
    [r.persisted?, r.errors.group_by_attribute.has_key?("password"),
     Member.find?(m.id.not_nil!).not_nil!.reset_password_token.to_s.matches?(/^[0-9a-f]{64}$/)].inspect
  },
  "rec_send_by_email_found" => -> {
    m = member_create("rec7@e.co")
    rec = Member.send_reset_password_instructions({"email" => m.email.not_nil!})
    [rec.persisted?, SENT.last[0] == :reset_password_instructions,
     Member.find?(m.id.not_nil!).not_nil!.reset_password_token.to_s.matches?(/^[0-9a-f]{64}$/)].inspect
  },
  "rec_send_by_email_missing" => -> {
    rec = Member.send_reset_password_instructions({"email" => "nobody@e.co"})
    [rec.persisted?, rec.errors.group_by_attribute.has_key?("email"),
     rec.errors.details["email"]?.try(&.map { |d| d[:error] })].inspect
  },
  "rec_period_valid" => -> {
    m = member_create("rec8@e.co")
    m.send_reset_password_instructions
    fresh = Member.find?(m.id.not_nil!).not_nil!.reset_password_period_valid?
    Member.find?(m.id.not_nil!).not_nil!
      .update_columns({"reset_password_sent_at" => Time.utc - 7.hours})
    [fresh, Member.find?(m.id.not_nil!).not_nil!.reset_password_period_valid?].inspect
  },
  # --- confirmable ---
  "conf_on_create" => -> {
    before = SENT.size
    m = member_create("conf1@e.co")
    [m.confirmation_token.not_nil!.matches?(/^[A-Za-z0-9_-]{20}$/),
     !m.confirmation_sent_at.nil?, m.confirmed?,
     SENT.size == before + 1,
     SENT.last == {:confirmation_instructions, m.confirmation_token.not_nil!}].inspect
  },
  "conf_confirm" => -> {
    m = member_create("conf2@e.co")
    first = m.confirm
    second = m.reload.confirm
    [first, Member.find?(m.id.not_nil!).not_nil!.confirmed?, second,
     m.errors.group_by_attribute.has_key?("email"),
     m.errors.details["email"]?.try(&.map { |d| d[:error] })].inspect
  },
  "conf_confirm_by_token" => -> {
    m = member_create("conf3@e.co")
    raw = SENT.last[1]
    r = Member.confirm_by_token(raw)
    [r.persisted?, r.confirmed?].inspect
  },
  "conf_confirm_by_token_invalid" => -> {
    r = Member.confirm_by_token("bogus-token-12345678")
    [r.persisted?, r.errors.group_by_attribute.has_key?("confirmation_token"),
     r.errors.details["confirmation_token"]?.try(&.map { |d| d[:error] })].inspect
  },
  "conf_confirm_by_token_blank" => -> {
    r = Member.confirm_by_token("")
    [r.persisted?, r.errors.details["confirmation_token"]?.try(&.map { |d| d[:error] })].inspect
  },
  "conf_period_expired" => -> {
    Member.confirm_within = 3.days
    begin
      m = member_create("conf4@e.co")
      m.update_columns({"confirmation_sent_at" => Time.utc - 4.days})
      r = m.reload.confirm
      [r, Member.find?(m.id.not_nil!).not_nil!.confirmed?,
       m.errors.details["email"]?.try(&.map { |d| d[:error] })].inspect
    ensure
      Member.confirm_within = nil
    end
  },
  "conf_active_for_authentication" => -> {
    m = member_create("conf5@e.co")
    before = [m.active_for_authentication?, m.inactive_message]
    m.confirm
    (before << Member.find?(m.id.not_nil!).not_nil!.active_for_authentication?).inspect
  },
  "conf_allow_unconfirmed" => -> {
    Member.allow_unconfirmed_access_for = 2.days
    begin
      m = member_create("conf6@e.co")
      m.update_columns({"confirmation_sent_at" => Time.utc - 1.day})
      m.reload.active_for_authentication?.to_s
    ensure
      Member.allow_unconfirmed_access_for = Time::Span.zero
    end
  },
  "conf_reconfirmable" => -> {
    m = member_create("conf7@e.co")
    m.confirm
    m.update({"email" => "newmail@e.co"})
    db = Member.find?(m.id.not_nil!).not_nil!
    postponed = [db.email, db.unconfirmed_email,
                 db.confirmation_token.not_nil!.matches?(/^[A-Za-z0-9_-]{20}$/),
                 SENT.last[0] == :confirmation_instructions]
    r = db.confirm
    after = Member.find?(m.id.not_nil!).not_nil!
    (postponed + [r, after.email, after.unconfirmed_email, after.confirmed?]).inspect
  },
  "conf_send_by_email_missing" => -> {
    r = Member.send_confirmation_instructions({"email" => "nobody@e.co"})
    [r.persisted?, r.errors.details["email"]?.try(&.map { |d| d[:error] })].inspect
  },
  "conf_skip_confirmation" => -> {
    before = SENT.size
    m = Member.new({"email" => "conf8@e.co"})
    m.password = "secret123"
    m.password_confirmation = "secret123"
    m.skip_confirmation!
    m.save
    [m.persisted?, m.confirmed?, SENT.size == before].inspect
  },
  # --- trackable ---
  "track_once" => -> {
    m = member_create("trk1@e.co")
    m.update_tracked_fields!(Devise::RequestInfo.new("1.2.3.4"))
    db = Member.find?(m.id.not_nil!).not_nil!
    [db.sign_in_count, !db.current_sign_in_at.nil?, !db.last_sign_in_at.nil?,
     db.current_sign_in_ip, db.last_sign_in_ip].inspect
  },
  "track_twice" => -> {
    m = member_create("trk2@e.co")
    m.update_tracked_fields!(Devise::RequestInfo.new("1.2.3.4"))
    first_at = Member.find?(m.id.not_nil!).not_nil!.current_sign_in_at
    m.update_tracked_fields!(Devise::RequestInfo.new("5.6.7.8"))
    db = Member.find?(m.id.not_nil!).not_nil!
    [db.sign_in_count, db.last_sign_in_at == first_at, db.last_sign_in_ip,
     db.current_sign_in_ip].inspect
  },
  "track_new_record_skipped" => -> {
    m = Member.new({"email" => "trk3@e.co"})
    m.password = "secret123"
    m.password_confirmation = "secret123"
    m.update_tracked_fields!(Devise::RequestInfo.new("1.2.3.4"))
    m.sign_in_count.nil?.to_s
  },
  # --- lockable ---
  "lock_strategies" => -> {
    [Member.lock_strategy_enabled?(:failed_attempts),
     Member.unlock_strategy_enabled?(:time), Member.unlock_strategy_enabled?(:email),
     Member.unlock_strategy_enabled?(:bogus)].inspect
  },
  "lock_attempts" => -> {
    Member.maximum_attempts = 3
    begin
      m = member_create("lck1@e.co")
      r1 = m.valid_for_authentication? { false }
      r2 = m.valid_for_authentication? { false }
      msg = m.unauthenticated_message
      [r1, Member.find?(m.id.not_nil!).not_nil!.failed_attempts, r2, msg].inspect
    ensure
      Member.maximum_attempts = 20
    end
  },
  "lock_locks_after_max" => -> {
    Member.maximum_attempts = 3
    begin
      m = member_create("lck2@e.co")
      3.times { m.valid_for_authentication? { false } }
      db = Member.find?(m.id.not_nil!).not_nil!
      locked = [db.access_locked?, !db.locked_at.nil?, db.failed_attempts,
                db.unlock_token.to_s.matches?(/^[0-9a-f]{64}$/),
                SENT.last[0] == :unlock_instructions, m.unauthenticated_message]
      (locked << m.valid_for_authentication? { true }).inspect
    ensure
      Member.maximum_attempts = 20
    end
  },
  "lock_unlock_access" => -> {
    Member.maximum_attempts = 3
    begin
      m = member_create("lck3@e.co")
      3.times { m.valid_for_authentication? { false } }
      m.unlock_access!
      db = Member.find?(m.id.not_nil!).not_nil!
      [db.access_locked?, db.failed_attempts, db.unlock_token.nil?].inspect
    ensure
      Member.maximum_attempts = 20
    end
  },
  "lock_expired" => -> {
    m = member_create("lck4@e.co")
    m.lock_access!(send_instructions: false)
    m.update_columns({"locked_at" => Time.utc - 2.hours})
    m.reload.access_locked?.to_s
  },
  "lock_unlock_by_token" => -> {
    m = member_create("lck5@e.co")
    m.lock_access!(send_instructions: false)
    raw = m.send_unlock_instructions
    r = Member.unlock_access_by_token(raw)
    wrong = Member.unlock_access_by_token("bogus-token-12345678")
    [r.persisted?, Member.find?(m.id.not_nil!).not_nil!.access_locked?,
     wrong.persisted?, wrong.errors.details["unlock_token"]?.try(&.map { |d| d[:error] })].inspect
  },
  "lock_last_attempt_message" => -> {
    Member.maximum_attempts = 3
    begin
      m = member_create("lck6@e.co")
      m.valid_for_authentication? { false }
      m.valid_for_authentication? { false }
      m.unauthenticated_message.inspect
    ensure
      Member.maximum_attempts = 20
    end
  },
  # --- timeoutable ---
  "t_out_recent"  => -> { member_create("tmo1@e.co").timedout?(Time.utc - 29.minutes).to_s },
  "t_out_expired" => -> { member_create("tmo2@e.co").timedout?(Time.utc - 31.minutes).to_s },
  "t_out_nil"     => -> { member_create("tmo3@e.co").timedout?(nil).inspect },
  "t_out_disabled" => -> {
    Member.timeout_in = nil
    begin
      member_create("tmo4@e.co").timedout?(Time.utc - 365.days).to_s
    ensure
      Member.timeout_in = 30.minutes
    end
  },
  # --- Devise::Mailer (headers only; body opt skips template rendering) ---
  "mail_reset" => -> {
    m = member_create("mal1@e.co")
    msg = Devise::Mailer.new.reset_password_instructions(m, "rawtok123", {"body" => "x"})
    [msg.subject, msg.to, msg.from].inspect
  },
  "mail_confirmation" => -> {
    m = member_create("mal2@e.co")
    msg = Devise::Mailer.new.confirmation_instructions(m, "rawtok123", {"body" => "x"})
    [msg.subject, msg.to, msg.from].inspect
  },
  "mail_unlock" => -> {
    m = member_create("mal3@e.co")
    msg = Devise::Mailer.new.unlock_instructions(m, "rawtok123", {"body" => "x"})
    [msg.subject, msg.to, msg.from].inspect
  },
}

describe "devise oracle" do
  CASES.each do |id, block|
    it id do
      expected = EXPECTED[id]? || fail("missing expected value for #{id}")
      escape(block.call).should eq expected
    end
  end
end
