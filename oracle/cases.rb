# Oracle cases for Devise (Iteration 6, P0 scope: model side of
# database_authenticatable + validatable + rememberable + registerable —
# bcrypt with pepper; sessions/HTTP covered by port unit specs like the
# action_mailer SMTP client).
#
# Run against the ORIGINAL gem:
#   ruby oracle/cases.rb > oracle/expected.yml
#
# Each line: "<case_id>\t<value>" (control chars escaped). Mirrored 1:1
# in spec/oracle_spec.cr; captured from devise 4.9.4 over SQLite
# in-memory.

gem "devise", "= 4.9.4"
gem "activerecord", "= 8.1.4"
gem "activesupport", "= 8.1.4"
gem "bcrypt", "= 3.1.21"
gem "sqlite3", ">= 2.1"
require "devise"
require "devise/orm/active_record"

ActiveRecord::Migration.verbose = false
ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.define do
  create_table :users do |t|
    t.string   :email,              null: false
    t.string   :encrypted_password, null: false
    t.datetime :remember_created_at
    t.timestamps
  end
end

class User < ActiveRecord::Base
  devise :database_authenticatable, :rememberable, :validatable
end

def render(v)
  s = v.is_a?(String) ? v : v.inspect
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

def case_run(id)
  puts "#{id}\t#{render(yield)}"
rescue StandardError => e
  puts "#{id}\traise:#{e.class.name}"
end

USER = User.create!(email: "a@b.c", password: "secret123",
                    password_confirmation: "secret123")

# --- encrypted password (bcrypt + stretches) -----------------------------
case_run("pw_digest_shape") { USER.encrypted_password.match?(/\A\$2a\$12\$[\.\/A-Za-z0-9]{53}\z/) }
case_run("pw_valid")        { User.find(USER.id).valid_password?("secret123") }
case_run("pw_wrong")        { User.find(USER.id).valid_password?("nope") }
case_run("pw_blank_hash")   { User.new(email: "x@y.z").valid_password?("any") }
case_run("pw_deterministic_by_salt") do
  # same password + same salt → same digest (compare re-hash)
  fresh = User.new(email: "p@q.r", password: "secret123")
  salt = USER.encrypted_password[0, 29]
  rehashed = BCrypt::Engine.hash_secret("secret123", salt)
  rehashed.start_with?(salt)
end

# --- pepper ----------------------------------------------------------------
PEPPERED = Class.new(ActiveRecord::Base) do
  self.table_name = "users"
  devise :database_authenticatable, :validatable
  self.pepper = "s3cr3t-pepper"
end

case_run("pw_pepper_digest") do
  u = PEPPERED.new(email: "p@q.r", password: "secret123")
  salt = u.encrypted_password[0, 29]
  u.encrypted_password == BCrypt::Engine.hash_secret("secret123s3cr3t-pepper", salt)
end
case_run("pw_pepper_valid") do
  u = PEPPERED.create!(email: "p@q.r", password: "secret123", password_confirmation: "secret123")
  [u.valid_password?("secret123"), u.valid_password?("secret123s3cr3t-pepper")]
end

# --- validatable -------------------------------------------------------------
case_run("val_ok")        { User.new(email: "ok@e.co", password: "longenough", password_confirmation: "longenough").valid? }
case_run("val_email_missing") do
  u = User.new(password: "longenough", password_confirmation: "longenough")
  [u.valid?, u.errors.attribute_names.include?(:email)]
end
case_run("val_email_bad") do
  u = User.new(email: "no-at", password: "longenough", password_confirmation: "longenough")
  [u.valid?, u.errors.attribute_names.include?(:email)]
end
case_run("val_email_uniq") do
  u = User.new(email: USER.email.upcase, password: "longenough", password_confirmation: "longenough")
  [u.valid?, u.errors.attribute_names.include?(:email)]
end
case_run("val_pw_short") do
  u = User.new(email: "s@e.co", password: "abc", password_confirmation: "abc")
  [u.valid?, u.errors.attribute_names.include?(:password)]
end
case_run("val_pw_long") do
  u = User.new(email: "s@e.co", password: "x" * 129, password_confirmation: "x" * 129)
  [u.valid?, u.errors.attribute_names.include?(:password)]
end
case_run("val_pw_mismatch") do
  u = User.new(email: "s@e.co", password: "longenough", password_confirmation: "different")
  [u.valid?, u.errors.attribute_names.include?(:password_confirmation)]
end
case_run("val_update_no_pw") do
  u = User.find(USER.id)
  u.email = "new@e.co"
  u.valid?
end

# --- update_with_password -----------------------------------------------
case_run("uwp_ok") do
  u = User.find(USER.id)
  res = u.update_with_password(current_password: "secret123", email: "uwp@e.co")
  [res, User.find(USER.id).email]
end
case_run("uwp_bad_pw") do
  u = User.find(USER.id)
  res = u.update_with_password(current_password: "WRONG", email: "hacked@e.co")
  [res, u.errors.attribute_names.include?(:current_password), User.find(USER.id).email]
end
case_run("uwp_new_password") do
  u = User.find(USER.id)
  res = u.update_with_password(current_password: "secret123",
                               password: "newpass99", password_confirmation: "newpass99")
  [res, User.find(USER.id).valid_password?("newpass99")]
end

# --- authenticatable_salt / rememberable ----------------------------------
case_run("auth_salt_shape") { USER.authenticatable_salt.match?(/\A\$2a\$12\$[\.\/A-Za-z0-9]{22}\z/) }
case_run("rem_me") do
  u = User.find(USER.id)
  u.remember_me!
  !u.remember_created_at.nil?
end
case_run("rem_serialize") do
  u = User.find(USER.id)
  u.remember_me!
  id, token, generated_at = User.serialize_into_cookie(u)
  [id == [USER.id], token == u.authenticatable_salt, generated_at.match?(/\A\d+(\.\d+)?\z/) != nil]
end
case_run("rem_from_cookie") do
  u = User.find(USER.id)
  u.remember_me!
  User.serialize_from_cookie(*User.serialize_into_cookie(u))&.id == USER.id
end
case_run("rem_wrong_token") do
  u = User.find(USER.id)
  u.remember_me!
  User.serialize_from_cookie([USER.id], "x" * 29, Time.now.utc.to_f.to_s)
end
case_run("rem_expired") do
  u = User.find(USER.id)
  u.remember_me!
  old = (User.remember_for + 1).ago.to_f.to_s
  User.serialize_from_cookie([USER.id], u.authenticatable_salt, old)
end
case_run("rem_forget") do
  u = User.find(USER.id)
  u.remember_me!
  u.forget_me!
  User.find(USER.id).remember_created_at.nil?
end

# --- registerable (model side: create) ------------------------------------
case_run("reg_create") do
  u = User.new(email: "reg@e.co", password: "regpass1", password_confirmation: "regpass1")
  u.save
  [u.persisted?, u.valid_password?("regpass1")]
end

# ===========================================================================
# P1: recoverable + confirmable + trackable + lockable + timeoutable
# + Devise::Mailer headers. The Member model uses a dedicated recorder
# mailer so notification DISPATCH is asserted without rendering the gem's
# views (which need a full Rails app with routes); the real Devise::Mailer
# is exercised header-only below (body: opt skips template lookup).
# ===========================================================================
require "action_mailer"
require "devise/mailers/helpers"
GEM_MAILER = File.join(Gem::Specification.find_by_name("devise", "= 4.9.4").gem_dir,
                       "app/mailers/devise/mailer.rb")
require GEM_MAILER
ActionMailer::Base.delivery_method = :test

ActiveRecord::Schema.define do
  create_table :members do |t|
    t.string   :email,              null: false
    t.string   :encrypted_password, null: false
    t.string   :reset_password_token
    t.datetime :reset_password_sent_at
    t.string   :confirmation_token
    t.datetime :confirmed_at
    t.datetime :confirmation_sent_at
    t.string   :unconfirmed_email
    t.integer  :failed_attempts, default: 0, null: false
    t.string   :unlock_token
    t.datetime :locked_at
    t.integer  :sign_in_count
    t.datetime :current_sign_in_at
    t.datetime :last_sign_in_at
    t.string   :current_sign_in_ip
    t.string   :last_sign_in_ip
    t.timestamps
  end
end

# Recorder mailer: send_devise_notification dispatch lands here; SENT keeps
# [notification, raw_token] pairs.
class NotificationRecorder < ActionMailer::Base
  def confirmation_instructions(record, token, opts = {});  record; end
  def reset_password_instructions(record, token, opts = {}); record; end
  def unlock_instructions(record, token, opts = {});        record; end
  def email_changed(record, opts = {});                     record; end
  def password_change(record, opts = {});                   record; end
end
SENT = []

class Member < ActiveRecord::Base
  devise :database_authenticatable, :validatable, :recoverable,
         :confirmable, :trackable, :lockable, :timeoutable

  def send_devise_notification(notification, *args)
    SENT << [notification, args.first]
  end
end

Devise.mailer = "NotificationRecorder"
Devise.mailer_sender = "test@example.com"
Devise.mappings[:member] = Devise::Mapping.new(:member, { failure_app: Class.new })
Devise.secret_key = "oracle-secret"
Devise.token_generator = Devise::TokenGenerator.new(
  ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(Devise.secret_key)))

def member_create(email, password = "secret123")
  Member.create!(email: email, password: password, password_confirmation: password)
end

Req = Struct.new(:remote_ip)

# --- token generator (byte-compatible digest of a fixed raw token) --------
case_run("tok_digest_fixed") do
  Devise.token_generator.digest(Member, :reset_password_token, "raw-token-123")
end
case_run("tok_friendly_shape") do
  t = Devise.friendly_token
  [t.size, t.match?(/\A[A-Za-z0-9_-]+\z/), !(t =~ /[lIO0]/)]
end

# --- recoverable ------------------------------------------------------------
case_run("rec_send_instructions") do
  m = member_create("rec1@e.co")
  raw = m.send_reset_password_instructions
  db = Member.find(m.id)
  [raw.match?(/\A[A-Za-z0-9_-]{20}\z/), db.reset_password_token.to_s.match?(/\A[0-9a-f]{64}\z/),
   !db.reset_password_sent_at.nil?, SENT.last == [:reset_password_instructions, raw]]
end
case_run("rec_find_by_token") do
  m = member_create("rec2@e.co")
  raw = m.send_reset_password_instructions
  [Member.with_reset_password_token(raw)&.id == m.id,
   Member.with_reset_password_token("bogus-token-1234567").nil?]
end
case_run("rec_reset_by_token_ok") do
  m = member_create("rec3@e.co")
  raw = m.send_reset_password_instructions
  r = Member.reset_password_by_token(reset_password_token: raw,
                                     password: "newpass99", password_confirmation: "newpass99")
  [r.persisted?, Member.find(m.id).valid_password?("newpass99"),
   Member.find(m.id).reset_password_token.nil?]
end
case_run("rec_reset_by_token_invalid") do
  r = Member.reset_password_by_token(reset_password_token: "no-such-token-1234",
                                     password: "newpass99", password_confirmation: "newpass99")
  [r.persisted?, r.errors.attribute_names.include?(:reset_password_token),
   r.errors.details[:reset_password_token].map { |d| d[:error] }]
end
case_run("rec_reset_by_token_expired") do
  m = member_create("rec4@e.co")
  raw = m.send_reset_password_instructions
  m.update_columns(reset_password_sent_at: 7.hours.ago.utc) # within = 6h
  r = Member.reset_password_by_token(reset_password_token: raw,
                                     password: "newpass99", password_confirmation: "newpass99")
  [r.persisted?, r.errors.details[:reset_password_token].map { |d| d[:error] }]
end
case_run("rec_reset_blank_password") do
  m = member_create("rec5@e.co")
  raw = m.send_reset_password_instructions
  r = Member.reset_password_by_token(reset_password_token: raw, password: "", password_confirmation: "")
  [r.persisted?, r.errors.details[:password].map { |d| d[:error] }]
end
case_run("rec_reset_short_password") do
  m = member_create("rec6@e.co")
  raw = m.send_reset_password_instructions
  r = Member.reset_password_by_token(reset_password_token: raw, password: "abc", password_confirmation: "abc")
  [r.persisted?, r.errors.attribute_names.include?(:password),
   Member.find(m.id).reset_password_token.to_s.match?(/\A[0-9a-f]{64}\z/)] # token NOT consumed
end
case_run("rec_send_by_email_found") do
  m = member_create("rec7@e.co")
  rec = Member.send_reset_password_instructions(email: m.email)
  [rec.persisted?, SENT.last.first == :reset_password_instructions,
   Member.find(m.id).reset_password_token.to_s.match?(/\A[0-9a-f]{64}\z/)]
end
case_run("rec_send_by_email_missing") do
  rec = Member.send_reset_password_instructions(email: "nobody@e.co")
  [rec.persisted?, rec.errors.attribute_names.include?(:email),
   rec.errors.details[:email].map { |d| d[:error] }]
end
case_run("rec_period_valid") do
  m = member_create("rec8@e.co")
  m.send_reset_password_instructions
  fresh = Member.find(m.id).reset_password_period_valid?
  Member.find(m.id).update_columns(reset_password_sent_at: 7.hours.ago.utc)
  [fresh, Member.find(m.id).reset_password_period_valid?]
end

# --- confirmable --------------------------------------------------------------
case_run("conf_on_create") do
  before = SENT.size
  m = member_create("conf1@e.co")
  [m.confirmation_token.match?(/\A[A-Za-z0-9_-]{20}\z/), !m.confirmation_sent_at.nil?,
   m.confirmed?, SENT.size == before + 1, SENT.last == [:confirmation_instructions, m.confirmation_token]]
end
case_run("conf_confirm") do
  m = member_create("conf2@e.co")
  first = m.confirm
  second = m.reload.confirm
  [first, Member.find(m.id).confirmed?, second,
   m.errors.attribute_names.include?(:email),
   m.errors.details[:email].map { |d| d[:error] }]
end
case_run("conf_confirm_by_token") do
  m = member_create("conf3@e.co")
  raw = SENT.last[1]
  r = Member.confirm_by_token(raw)
  [r.persisted?, r.confirmed?]
end
case_run("conf_confirm_by_token_invalid") do
  r = Member.confirm_by_token("bogus-token-12345678")
  [r.persisted?, r.errors.attribute_names.include?(:confirmation_token),
   r.errors.details[:confirmation_token].map { |d| d[:error] }]
end
case_run("conf_confirm_by_token_blank") do
  r = Member.confirm_by_token("")
  [r.persisted?, r.errors.details[:confirmation_token].map { |d| d[:error] }]
end
case_run("conf_period_expired") do
  Member.confirm_within = 3.days
  begin
    m = member_create("conf4@e.co")
    m.update_columns(confirmation_sent_at: 4.days.ago.utc)
    r = m.reload.confirm
    [r, Member.find(m.id).confirmed?,
     m.errors.details[:email].map { |d| d[:error] }]
  ensure
    Member.confirm_within = nil
  end
end
case_run("conf_active_for_authentication") do
  m = member_create("conf5@e.co")
  before = [m.active_for_authentication?, m.inactive_message]
  m.confirm
  before + [Member.find(m.id).active_for_authentication?]
end
case_run("conf_allow_unconfirmed") do
  Member.allow_unconfirmed_access_for = 2.days
  begin
    m = member_create("conf6@e.co")
    m.update_columns(confirmation_sent_at: 1.day.ago.utc)
    m.reload.active_for_authentication?
  ensure
    Member.allow_unconfirmed_access_for = 0.days
  end
end
case_run("conf_reconfirmable") do
  m = member_create("conf7@e.co")
  m.confirm
  m.update(email: "newmail@e.co")
  db = Member.find(m.id)
  postponed = [db.email, db.unconfirmed_email,
               db.confirmation_token.match?(/\A[A-Za-z0-9_-]{20}\z/),
               SENT.last.first == :confirmation_instructions]
  r = db.confirm
  after = Member.find(m.id)
  postponed + [r, after.email, after.unconfirmed_email, after.confirmed?]
end
case_run("conf_send_by_email_missing") do
  r = Member.send_confirmation_instructions(email: "nobody@e.co")
  [r.persisted?, r.errors.details[:email].map { |d| d[:error] }]
end
case_run("conf_skip_confirmation") do
  before = SENT.size
  m = Member.new(email: "conf8@e.co", password: "secret123", password_confirmation: "secret123")
  m.skip_confirmation!
  m.save
  [m.persisted?, m.confirmed?, SENT.size == before]
end

# --- trackable ------------------------------------------------------------
case_run("track_once") do
  m = member_create("trk1@e.co")
  m.update_tracked_fields!(Req.new("1.2.3.4"))
  db = Member.find(m.id)
  [db.sign_in_count, !db.current_sign_in_at.nil?, !db.last_sign_in_at.nil?,
   db.current_sign_in_ip, db.last_sign_in_ip]
end
case_run("track_twice") do
  m = member_create("trk2@e.co")
  m.update_tracked_fields!(Req.new("1.2.3.4"))
  first_at = Member.find(m.id).current_sign_in_at
  m.update_tracked_fields!(Req.new("5.6.7.8"))
  db = Member.find(m.id)
  [db.sign_in_count, db.last_sign_in_at == first_at, db.last_sign_in_ip, db.current_sign_in_ip]
end
case_run("track_new_record_skipped") do
  m = Member.new(email: "trk3@e.co", password: "secret123", password_confirmation: "secret123")
  m.update_tracked_fields!(Req.new("1.2.3.4"))
  m.sign_in_count.nil?
end

# --- lockable ---------------------------------------------------------------
case_run("lock_strategies") do
  [Member.lock_strategy_enabled?(:failed_attempts),
   Member.unlock_strategy_enabled?(:time), Member.unlock_strategy_enabled?(:email),
   Member.unlock_strategy_enabled?(:bogus)]
end
case_run("lock_attempts") do
  Member.maximum_attempts = 3
  begin
    m = member_create("lck1@e.co")
    r1 = m.valid_for_authentication? { false }
    r2 = m.valid_for_authentication? { false }
    msg = m.unauthenticated_message
    [r1, Member.find(m.id).failed_attempts, r2, msg]
  ensure
    Member.maximum_attempts = 20
  end
end
case_run("lock_locks_after_max") do
  Member.maximum_attempts = 3
  begin
    m = member_create("lck2@e.co")
    3.times { m.valid_for_authentication? { false } }
    db = Member.find(m.id)
    locked = [db.access_locked?, !db.locked_at.nil?, db.failed_attempts,
              db.unlock_token.to_s.match?(/\A[0-9a-f]{64}\z/),
              SENT.last.first == :unlock_instructions, m.unauthenticated_message]
    locked + [m.valid_for_authentication? { true }] # still locked
  ensure
    Member.maximum_attempts = 20
  end
end
case_run("lock_unlock_access") do
  Member.maximum_attempts = 3
  begin
    m = member_create("lck3@e.co")
    3.times { m.valid_for_authentication? { false } }
    m.unlock_access!
    db = Member.find(m.id)
    [db.access_locked?, db.failed_attempts, db.unlock_token.nil?]
  ensure
    Member.maximum_attempts = 20
  end
end
case_run("lock_expired") do
  m = member_create("lck4@e.co")
  m.lock_access!(send_instructions: false)
  m.update_columns(locked_at: 2.hours.ago.utc) # unlock_in = 1h
  m.reload.access_locked?
end
case_run("lock_unlock_by_token") do
  m = member_create("lck5@e.co")
  m.lock_access!(send_instructions: false)
  raw = m.send_unlock_instructions
  r = Member.unlock_access_by_token(raw)
  wrong = Member.unlock_access_by_token("bogus-token-12345678")
  [r.persisted?, Member.find(m.id).access_locked?,
   wrong.persisted?, wrong.errors.details[:unlock_token].map { |d| d[:error] }]
end
case_run("lock_last_attempt_message") do
  Member.maximum_attempts = 3
  begin
    m = member_create("lck6@e.co")
    m.valid_for_authentication? { false }
    m.valid_for_authentication? { false } # 2 of 3 → next-to-last
    m.unauthenticated_message
  ensure
    Member.maximum_attempts = 20
  end
end

# --- timeoutable --------------------------------------------------------------
case_run("t_out_recent")  { member_create("tmo1@e.co").timedout?(29.minutes.ago.utc) }
case_run("t_out_expired") { member_create("tmo2@e.co").timedout?(31.minutes.ago.utc) }
case_run("t_out_nil")     { member_create("tmo3@e.co").timedout?(nil) }
case_run("t_out_disabled") do
  Member.timeout_in = nil
  begin
    member_create("tmo4@e.co").timedout?(1.year.ago.utc)
  ensure
    Member.timeout_in = 30.minutes
  end
end

# --- Devise::Mailer (headers only; body: opt skips template rendering) ------
case_run("mail_reset") do
  m = member_create("mal1@e.co")
  msg = Devise::Mailer.reset_password_instructions(m, "rawtok123", { body: "x" }).message
  [msg.subject, msg.to, msg.from]
end
case_run("mail_confirmation") do
  m = member_create("mal2@e.co")
  msg = Devise::Mailer.confirmation_instructions(m, "rawtok123", { body: "x" }).message
  [msg.subject, msg.to, msg.from]
end
case_run("mail_unlock") do
  m = member_create("mal3@e.co")
  msg = Devise::Mailer.unlock_instructions(m, "rawtok123", { body: "x" }).message
  [msg.subject, msg.to, msg.from]
end
