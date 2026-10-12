# Oracle cases for the Devise HTTP layer (Phase H) — captured from
# devise 4.9.4 inside the throwaway Rails 8.1.4 app (tmp/http_app).
#
# Run against the ORIGINAL gem (from tmp/http_app):
#   ruby bin/rails runner ../oracle/http_cases.rb > ../oracle/http_expected.yml
#
# Each line: "<case_id>\t<value>". Mirrored 1:1 in spec/http_oracle_spec.cr.
# Covers: route table (names/verbs/paths), registration/login/logout
# redirects + flash strings, warden session key format, remember_user_token
# cookie name, failure-app behavior (401 + Location), password reset
# redirect chain, omniauth passthru.
#
# App setup pinned by this oracle (tmp/http_app): User with all devise
# modules + omniauthable(google_oauth2), allow_forgery_protection = false,
# test mailer, hosts cleared. Every scenario runs in a fresh integration
# session so flash never leaks between cases.

def line(id, value)
  puts "#{id}\t#{value}"
end

flash_s = ->(s) { s.flash.to_a.map { |k, v| "#{k}=#{v}" }.sort.join(",") }

# --- route table -----------------------------------------------------
routes = Rails.application.routes.routes.map do |r|
  verb = r.verb.respond_to?(:source) ? r.verb.source : r.verb.to_s
  verb = verb.gsub(%r{\A\^|\$\z}, "")
  prefix = r.name ? r.name.to_s : ""
  "#{prefix}|#{verb}|#{r.path.spec.to_s.sub("(.:format)", "")}|#{r.defaults[:controller]}##{r.defaults[:action]}"
end
routes.sort.each_with_index { |r, i| line("http_route_#{sprintf("%02d", i)}", r) }

User.delete_all
ActionMailer::Base.deliveries.clear

# --- registration -----------------------------------------------------
app = ActionDispatch::Integration::Session.new(Rails.application)
app.post "/users", params: {
  "user" => {"email" => "u@example.com", "password" => "secret123",
             "password_confirmation" => "secret123"}
}
line("http_register_status", app.response.status)
line("http_register_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_register_flash", flash_s.(app))
line("http_register_session_keys", app.session.to_h.keys.map(&:to_s).sort.join(","))
line("http_register_signs_in_automatically", app.session["warden.user.user.key"].nil?)

# --- sign out / sign in (confirmed user) ------------------------------
User.update_all(confirmed_at: Time.current)

app.delete "/users/sign_out"
line("http_signout_status", app.response.status)
line("http_signout_flash", flash_s.(app))

app.get "/users/sign_in"
line("http_signin_form_status", app.response.status)

app.post "/users/sign_in", params: {
  "user" => {"email" => "u@example.com", "password" => "wrong"}
}
line("http_signin_bad_status", app.response.status)
line("http_signin_bad_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_signin_bad_flash", flash_s.(app))
line("http_signin_bad_session_keys", app.session.to_h.keys.map(&:to_s).sort.join(","))

app.post "/users/sign_in", params: {
  "user" => {"email" => "u@example.com", "password" => "secret123"}
}
line("http_signin_status", app.response.status)
line("http_signin_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_signin_flash", flash_s.(app))
line("http_signin_session_keys", app.session.to_h.keys.map(&:to_s).sort.join(","))
key = app.session["warden.user.user.key"]
line("http_warden_key_format",
     key.is_a?(Array) ? key.map { |part| part.is_a?(Array) ? "[#{part.map(&:class).join(",")}]" : part.class.to_s }.join("+") : key.class.to_s)
line("http_warden_key_id", key.is_a?(Array) ? key[0][0].to_s : "")

# signed-in: new_user_session redirects away
app.get "/users/sign_in"
line("http_signin_form_signed_in_status", app.response.status)
line("http_signin_form_signed_in_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))

# --- authenticate_user! failure app ----------------------------------
fresh = ActionDispatch::Integration::Session.new(Rails.application)
fresh.get "/private"
line("http_guard_unauth_status", fresh.response.status)
line("http_guard_unauth_location", fresh.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_guard_unauth_flash", flash_s.(fresh))

auth = ActionDispatch::Integration::Session.new(Rails.application)
auth.post "/users/sign_in", params: {
  "user" => {"email" => "u@example.com", "password" => "secret123"}
}
auth.get "/private"
line("http_guard_auth_status", auth.response.status)
line("http_guard_auth_body", auth.response.body)

# --- rememberable -----------------------------------------------------
rem = ActionDispatch::Integration::Session.new(Rails.application)
rem.post "/users/sign_in", params: {
  "user" => {"email" => "u@example.com", "password" => "secret123",
             "remember_me" => "1"}
}
all_cookies = rem.response.headers["Set-Cookie"]
all_cookies = all_cookies.join("\n") if all_cookies.is_a?(Array)
cookie_names = all_cookies.to_s.split("\n")
  .map { |c| c.split("=").first }.reject { |n| n.start_with?("_http_app_session") }.sort
line("http_remember_cookie_names", cookie_names.join(","))

# remember cookie survives a fresh session (no session cookie)
set_cookie = rem.response.headers["Set-Cookie"]
set_cookie = set_cookie.join("\n") if set_cookie.is_a?(Array)
remember_cookie = set_cookie.to_s.split("\n")
  .find { |c| c.start_with?("remember_user_token") }.to_s.split(";").first
rem3 = ActionDispatch::Integration::Session.new(Rails.application)
rem3.get "/private", headers: {"Cookie" => remember_cookie}
line("http_remember_auto_sign_in_status", rem3.response.status)

# --- password reset (raw token from the mail) -------------------------
ActionMailer::Base.deliveries.clear
pw = ActionDispatch::Integration::Session.new(Rails.application)
pw.post "/users/password", params: {
  "user" => {"email" => "u@example.com"}
}
line("http_pw_request_status", pw.response.status)
line("http_pw_request_location", pw.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_pw_request_flash", flash_s.(pw))
mail = ActionMailer::Base.deliveries.last
token = mail.body.to_s[/reset_password_token=([^\\"&]+)/, 1]
line("http_pw_token_present", !token.nil?)

pw.get "/users/password/edit", params: {"reset_password_token" => token}
line("http_pw_edit_status", pw.response.status)

pw.put "/users/password", params: {
  "user" => {"reset_password_token" => token,
             "password" => "newpass123", "password_confirmation" => "newpass123"}
}
line("http_pw_update_status", pw.response.status)
line("http_pw_update_location", pw.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_pw_update_flash", flash_s.(pw))
line("http_pw_new_password_works", User.last.valid_password?("newpass123"))

# --- confirmation (raw token from the mail) ---------------------------
ActionMailer::Base.deliveries.clear
User.update_all(confirmed_at: nil)
User.last.send(:generate_confirmation_token!)
User.last.send(:send_confirmation_instructions)
cmail = ActionMailer::Base.deliveries.last
ctoken = cmail.body.to_s[/confirmation_token=([^\\"&]+)/, 1]
cf = ActionDispatch::Integration::Session.new(Rails.application)
cf.get "/users/confirmation", params: {"confirmation_token" => ctoken}
line("http_confirm_status", cf.response.status)
line("http_confirm_location", cf.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("http_confirm_flash", flash_s.(cf))
line("http_confirm_confirmed", !User.last.confirmed_at.nil?)

# --- omniauth passthru ------------------------------------------------
oa = ActionDispatch::Integration::Session.new(Rails.application)
oa.get "/users/auth/google_oauth2"
line("http_omniauth_passthru_status", oa.response.status)
