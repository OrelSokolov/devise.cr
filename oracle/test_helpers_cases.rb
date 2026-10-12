# Oracle cases for Devise::Test::IntegrationHelpers (devise 4.9.4):
# sign_in/sign_out bypassing the sign-in form. Run against the ORIGINAL
# gem (from tmp/http_app):
#   ruby bin/rails runner ../oracle/test_helpers_cases.rb > ../oracle/test_helpers_expected.yml
#
# The helper bodies are reproduced verbatim from
# Devise::Test::IntegrationHelpers (scope ||= Devise.find_scope! →
# login_as/logout of Warden::Test::Helpers); the minitest setup/teardown
# wiring (Warden.test_mode!/test_reset!) is replaced by explicit calls —
# the user-visible contract (session key, authenticated requests, sign
# out) is what gets captured.
#
# Each line: "<case_id>\t<value>". Mirrored in spec/test_helpers_spec.cr.

def line(id, value)
  puts "#{id}\t#{value}"
end

Warden.test_mode!
app = ActionDispatch::Integration::Session.new(Rails.application)
app.extend(Warden::Test::Helpers)

# Devise::Test::IntegrationHelpers#sign_in / #sign_out, verbatim bodies.
def app.sign_in(resource, scope: nil)
  scope ||= Devise::Mapping.find_scope!(resource)
  login_as(resource, scope: scope)
end

def app.sign_out(resource_or_scope)
  scope = Devise::Mapping.find_scope!(resource_or_scope)
  logout scope
end

User.delete_all
User.connection.execute("DELETE FROM sqlite_sequence WHERE name='users'") rescue nil
Rails.application.reload_routes! # populate Devise.mappings (devise_for)
user = User.create!(email: "u@example.com", password: "secret123",
                    confirmed_at: Time.current)

# --- find_scope ---------------------------------------------------------
line("th_find_scope_class", Devise::Mapping.find_scope!(User))
line("th_find_scope_instance", Devise::Mapping.find_scope!(user))

# --- sign_in via helper -------------------------------------------------
app.sign_in(user)
app.get "/private"
line("th_signed_in_private_status", app.response.status)
line("th_signed_in_private_body", app.response.body.strip)
key = app.session["warden.user.user.key"]
line("th_signin_key_present", !key.nil?)
line("th_warden_key_format",
     key.is_a?(Array) ? key.map { |part| part.is_a?(Array) ? "[#{part.map(&:class).join(",")}]" : part.class.to_s }.join("+") : key.class.to_s)
line("th_warden_key_id", key.is_a?(Array) ? key[0][0].to_s : "")

# require_no_authentication now redirects (already signed in)
app.get "/users/sign_in"
line("th_signed_in_signin_status", app.response.status)
line("th_signed_in_signin_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))

# explicit scope: same session key
app2 = ActionDispatch::Integration::Session.new(Rails.application)
app2.extend(Warden::Test::Helpers)
def app2.sign_in(resource, scope: nil)
  scope ||= Devise::Mapping.find_scope!(resource)
  login_as(resource, scope: scope)
end
app2.sign_in(user, scope: :user)
app2.get "/private"
line("th_scope_explicit_private_status", app2.response.status)

# --- sign_out via helper ------------------------------------------------
app.sign_out(:user)
app.get "/private"
line("th_signout_private_status", app.response.status)
line("th_signout_private_location", app.response.headers["Location"].to_s.sub("http://www.example.com", ""))
line("th_signout_key_present", !app.session["warden.user.user.key"])

# sign_out accepts the resource too
app3 = ActionDispatch::Integration::Session.new(Rails.application)
app3.extend(Warden::Test::Helpers)
def app3.sign_in(resource, scope: nil)
  scope ||= Devise::Mapping.find_scope!(resource)
  login_as(resource, scope: scope)
end
def app3.sign_out(resource_or_scope)
  scope = Devise::Mapping.find_scope!(resource_or_scope)
  logout scope
end
app3.sign_in(user)
app3.sign_out(user)
app3.get "/private"
line("th_signout_via_resource_status", app3.response.status)

Warden.test_reset!
