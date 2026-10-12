# Oracle cases for the devise i18n layer (P2): the dictionary shipped by
# the gem (config/locales/en.yml — the ONLY locale devise distributes;
# community translations live in the wiki/rails-i18n) plus the I18n call
# contract the gem uses:
#
#   * flash:    I18n.t("<resource>.<kind>", scope: "devise.<controller>")
#   * failure:  I18n.t("<resource>.<message>", scope: "devise.failure",
#               authentication_keys: ..., default: [message])
#   * mailer:   I18n.t(:"<resource>_subject", scope: [:devise, :mailer, key],
#               default: [:subject, key.humanize])
#   * errors:   I18n.t("errors.messages.not_saved", count:, resource:)
#               (one/other pluralization, %{count}/%{resource})
#
# Run against the ORIGINAL gems:
#   ruby oracle/i18n_cases.rb > oracle/i18n_expected.yml
#
# Mirrored in spec/i18n_spec.cr. Line protocol: "<id>\t<value>".

def render(v)
  s = v.is_a?(String) ? v : v.inspect
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

def case_run(id)
  puts "#{id}\t#{render(yield)}"
rescue StandardError => e
  puts "#{id}\traise:#{e.class.name}"
end

gem "i18n"
gem "devise", "= 4.9.4"

require "i18n"
require "yaml"
require "tmpdir"

# key.to_s.humanize of the gem call, inlined (avoids an activesupport
# dependency): "reset_password_instructions".humanize etc.
HUMANIZED = {
  reset_password_instructions: "Reset password instructions",
  confirmation_instructions: "Confirmation instructions",
}

EN_YML = Gem::Specification.find_by_name("devise", "= 4.9.4").gem_dir +
         "/config/locales/en.yml"
I18n.available_locales = [:en, :ru]
I18n.enforce_available_locales = false
I18n.backend.send(:load_file, EN_YML) # I18n.backend.send(:load_file, EN_YML)

# Full community-style ru dictionary (the wiki convention: the same tree
# as en.yml under a different top-level locale key).
require "tmpdir"
ru_dir = Dir.mktmpdir("devise_ru")
RU_YML = File.join(ru_dir, "devise.ru.yml")
File.write(RU_YML, <<~YML)
  ru:
    devise:
      sessions:
        signed_in: "Вход в систему выполнен."
      failure:
        invalid: "Неверный %{authentication_keys} или пароль."
    errors:
      messages:
        not_saved:
          one: "Не удалось сохранить %{resource}: обнаружена %{count} ошибка"
          other: "Не удалось сохранить %{resource}: обнаружено %{count} ошибок"
YML
I18n.backend.send(:load_file, RU_YML)

# --- the shipped dictionary ---------------------------------------------
def flat_keys(obj, prefix = "")
  obj.each_with_object([]) do |(k, v), keys|
    path = prefix.empty? ? k.to_s : "#{prefix}.#{k}"
    v.is_a?(Hash) ? keys.concat(flat_keys(v, path)) : keys << path
  end
end

EN_TREE = YAML.unsafe_load_file(EN_YML)
case_run("i18n_devise_keys")  { flat_keys(EN_TREE["en"]["devise"]).sort }
case_run("i18n_errors_keys")  { flat_keys(EN_TREE["en"]["errors"]).sort }
case_run("i18n_en_only")      { %w[en.yml].join(",") } # devise ships en only

# --- flash lookup (devise_controller#find_message) ------------------------
case_run("i18n_flash_signed_in") do
  I18n.t("user.signed_in", scope: "devise.sessions", default: [:signed_in])
end
case_run("i18n_flash_welcome") do
  I18n.t("user.signed_up", scope: "devise.registrations", default: [:signed_up])
end

# --- failure_app#i18n_message ---------------------------------------------
case_run("i18n_failure_invalid") do
  I18n.t("user.invalid", scope: "devise.failure", default: [:invalid],
        authentication_keys: "Email")
end
case_run("i18n_failure_locked") do
  I18n.t("user.locked", scope: "devise.failure", default: [:locked],
        authentication_keys: "Email")
end

# --- mailer subject_for ----------------------------------------------------
case_run("i18n_mailer_reset_subject") do
  I18n.t(:user_subject, scope: [:devise, :mailer, :reset_password_instructions],
        default: [:subject, HUMANIZED[:reset_password_instructions]])
end
case_run("i18n_mailer_confirmation_subject") do
  I18n.t(:user_subject, scope: [:devise, :mailer, :confirmation_instructions],
        default: [:subject, HUMANIZED[:confirmation_instructions]])
end

# --- errors.messages.not_saved (plural + interpolation) -------------------
case_run("i18n_not_saved_one") do
  I18n.t("errors.messages.not_saved", count: 1, resource: "User")
end
case_run("i18n_not_saved_other") do
  I18n.t("errors.messages.not_saved", count: 3, resource: "User")
end

# --- a full community locale (wiki convention) -----------------------------
case_run("i18n_ru_flash_signed_in") do
  I18n.locale = :ru
  I18n.t("user.signed_in", scope: "devise.sessions", default: [:signed_in])
end
case_run("i18n_ru_failure_invalid") do
  I18n.locale = :ru
  I18n.t("user.invalid", scope: "devise.failure", default: [:invalid],
        authentication_keys: "Почта")
end
case_run("i18n_ru_not_saved_other") do
  I18n.locale = :ru
  I18n.t("errors.messages.not_saved", count: 3, resource: "Пользователь")
end
