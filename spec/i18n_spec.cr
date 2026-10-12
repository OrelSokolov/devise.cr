# i18n oracle spec: the Crystal port reproduces oracle/i18n_expected.yml
# (captured from devise 4.9.4 + ruby-i18n — see oracle/i18n_cases.rb): the
# shipped dictionary keys, the flash/failure/mailer lookup chains and the
# errors.messages.not_saved pluralization.
#
# Documented deviation: a key missing from the CURRENT locale falls back
# to en (Ruby-i18n would emit "Translation missing"); the ru cases use a
# full tree for the keys they read.

require "spec"
require "../src/devise_cr"

I18N_EXPECTED = begin
  hash = {} of String => String
  File.read("#{__DIR__}/../oracle/i18n_expected.yml").each_line do |line|
    if line.includes?('\t')
      id, value = line.split('\t', 2)
      hash[id] = value.chomp
    end
  end
  hash
end

def i18n_escape(s : String) : String
  s.gsub("\\", "\\\\\\\\").gsub("\n", "\\n").gsub("\t", "\\t").gsub("\r", "\\r")
end

# Ruby Array#inspect rendering of a list of dot-paths.
def ruby_inspect(keys : Array(String)) : String
  "[" + keys.map { |k| %("#{k}") }.join(", ") + "]"
end

def flatten_tree(tree : Devise::I18n::Tree, prefix : String = "") : Array(String)
  keys = [] of String
  case tree
  when Hash
    tree.each do |k, v|
      path = prefix.empty? ? k : "#{prefix}.#{k}"
      if v.is_a?(Hash)
        keys.concat(flatten_tree(v, path))
      else
        keys << path
      end
    end
  end
  keys
end

def en_tree : Devise::I18n::Tree
  Devise::I18n.en
end

RU_YML = <<-YML
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

I18N_CASES = {
  # --- the shipped dictionary ---
  "i18n_devise_keys" => -> {
    ruby_inspect(flatten_tree(en_tree.as(Hash)["devise"].as(Devise::I18n::Tree)).sort)
  },
  "i18n_errors_keys" => -> {
    ruby_inspect(flatten_tree(en_tree.as(Hash)["errors"].as(Devise::I18n::Tree)).sort)
  },
  "i18n_en_only" => -> { "en.yml" },
  # --- flash lookup ---
  "i18n_flash_signed_in" => -> {
    Devise.t("user.signed_in", scope: "devise.sessions")
  },
  "i18n_flash_welcome" => -> {
    Devise.t("user.signed_up", scope: "devise.registrations")
  },
  # --- failure lookup ---
  "i18n_failure_invalid" => -> {
    Devise.t("user.invalid", scope: "devise.failure", authentication_keys: "Email")
  },
  "i18n_failure_locked" => -> {
    Devise.t("user.locked", scope: "devise.failure", authentication_keys: "Email")
  },
  # --- mailer subject_for ---
  "i18n_mailer_reset_subject" => -> {
    Devise.t("user_subject", scope: "devise.mailer.reset_password_instructions")
  },
  "i18n_mailer_confirmation_subject" => -> {
    Devise.t("user_subject", scope: "devise.mailer.confirmation_instructions")
  },
  # --- errors.messages.not_saved (plural + interpolation) ---
  "i18n_not_saved_one" => -> {
    Devise.t("errors.messages.not_saved", count: 1, resource: "User")
  },
  "i18n_not_saved_other" => -> {
    Devise.t("errors.messages.not_saved", count: 3, resource: "User")
  },
}

describe "devise i18n oracle (en)" do
  I18N_CASES.each do |id, block|
    it id do
      expected = I18N_EXPECTED[id]? || fail("missing expected value for #{id}")
      i18n_escape(block.call.to_s).should eq expected
    end
  end
end

describe "devise i18n oracle (ru locale file)" do
  it "loads a community-style locale and switches lookups" do
    path = "#{__DIR__}/../tmp/devise_ru_spec.yml"
    File.write(path, RU_YML)
    Devise.load_locale(path)
    Devise::I18n.loaded_locales.should contain("ru")

    Devise.locale = "ru"
    begin
      Devise.t("user.signed_in", scope: "devise.sessions")
        .should eq I18N_EXPECTED["i18n_ru_flash_signed_in"]
      Devise.t("user.invalid", scope: "devise.failure", authentication_keys: "Почта")
        .should eq I18N_EXPECTED["i18n_ru_failure_invalid"]
      Devise.t("errors.messages.not_saved", count: 3, resource: "Пользователь")
        .should eq I18N_EXPECTED["i18n_ru_not_saved_other"]
      # missing key in ru → en fallback (documented deviation)
      Devise.t("user.locked", scope: "devise.failure")
        .should eq I18N_EXPECTED["i18n_failure_locked"]
    ensure
      Devise.locale = "en"
    end
  end
end
