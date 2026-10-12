# Devise i18n (P2): словарь en.yml 1:1 с гемом (devise 4.9.4 шлёт только
# en — остальные локали по конвенции wiki: тот же YAML-тре под другим
# верхним ключом) + I18n-контракт вызовов гема:
#
#   * flash:    I18n.t("<resource>.<kind>", scope: "devise.<controller>")
#               (ресурс-префикс промахивается → ключ без него, как
#               default-цепочка I18n)
#   * failure:  I18n.t("<resource>.<message>", scope: "devise.failure",
#               authentication_keys: ...) с интерполяцией
#   * mailer:   I18n.t(:"<resource>_subject", scope: [:devise, :mailer,
#               key], default: [:subject, key.humanize]) →
#               "<resource>_subject" промах → "subject"
#   * errors:   errors.messages.not_saved — one/other по count
#
# Оракул: oracle/i18n_cases.rb → oracle/i18n_expected.yml. Отклонения от
# Ruby-I18n: отсутствующий ключ в текущей локали отдаётся en-фоллбеком
# (Ruby-I18n вернул бы "Translation missing"); en-словарь запекается в
# бинарь compile-time (read_file), дополнительные локали — boot-time
# Devise::I18n.register_yaml(loc, yaml) (шарды-словари) или рантайм
# Devise.load_locale(path).

require "yaml"

module Devise
  module I18n
    # Nil-узел = отсутствующий ключ (как у ruby-I18n: YAML-nil leaf
    # отдаёт "Translation missing", а не пустую строку).
    alias Tree = String | Hash(String, Tree) | Nil

    # Bundled en dictionary (compile-time, byte-identical to the gem's
    # config/locales/en.yml).
    EN_YAML = {{ read_file("#{__DIR__}/locales/en.yml") }}.strip

    # locale → словарь (верхний ключ YAML = имя локали — как
    # I18n.backend.load_file). Перезаписывает существующую.
    @@locales = {} of String => Tree
    # locale → сырой YAML, зарегистрированный boot-time без файла
    # (аналог railtie I18n.load_path.concat — шарды-словари вроде
    # devise-i18n.cr запекают YAML compile-time и регистрируют при
    # require). Парсится лениво, при первом lookup.
    @@raw_locales = {} of String => String
    @@locale : String = "en"

    def self.locale : String
      @@locale
    end

    def self.locale=(loc : String) : String
      @@locale = loc
    end

    def self.load_locale(path : String) : Nil
      tree = convert(YAML.parse(File.read(path)).raw)
      as_hash = tree.as(Hash(String, Tree))
      as_hash.each do |loc, dict|
        @@locales[loc] = dict
      end
    end

    def self.loaded_locales : Array(String)
      (@@locales.keys + @@raw_locales.keys + ["en"]).uniq.sort
    end

    # Boot-time регистрация словаря сырой YAML-строкой (без файла —
    # запекается в бинарь шарды-словаря). Аналог добавления файлов в
    # I18n.load_path на инициализации railtie. Рантайм-запись локали
    # не затрагивает: словарь парсится лениво при первом lookup.
    def self.register_yaml(loc : String, yaml : String) : Nil
      @@raw_locales[loc] = yaml
      @@locales.delete(loc) # сброс кэша при перерегистрации
    end

    # en-словарь (парсится лениво, один раз). Зарегистрированный
    # devise-i18n-словарь en — надмножество словаря самого гема.
    def self.en : Tree
      @@locales["en"] ||= if raw = @@raw_locales["en"]?
                            convert(YAML.parse(raw).raw).as(Hash(String, Tree))["en"]?
                          else
                            convert(YAML.parse(EN_YAML).raw).as(Hash(String, Tree))["en"]
                          end
    end

    # Словарь текущей локали (nil пока не загружена — lookup уйдёт в en).
    def self.current : Tree?
      return en if @@locale == "en"
      if (raw = @@raw_locales[@@locale]?) && !@@locales.has_key?(@@locale)
        if dict = convert(YAML.parse(raw).raw).as(Hash(String, Tree))[@@locale]?
          @@locales[@@locale] = dict
        end
      end
      @@locales[@@locale]?
    end

    # YAML-узел → String-ключное дерево (nil остаётся nil — семантика
    # missing у ruby-I18n).
    private def self.convert(raw) : Tree
      node = raw.is_a?(YAML::Any) ? raw.raw : raw
      case node
      when Hash
        h = {} of String => Tree
        node.each { |k, v| h[k.to_s] = convert(v) }
        h
      when Nil
        nil
      else
        node.to_s
      end
    end

    # Лукап по dot-пути. Возвращает узел + флаг наличия пути: ключ
    # со значением nil — это nil-узел (ruby-I18n: "Translation missing"),
    # а не отсутствующий путь.
    private def self.dig(tree : Tree, path : String) : {Tree, Bool}
      node = tree
      path.split('.').each do |key|
        return {nil, false} unless node.is_a?(Hash)
        return {nil, false} unless node.has_key?(key)
        node = node[key]
      end
      {node, true}
    end

    # Hash-узел = one/other по count; nil/промах подключа → nil.
    private def self.pick_string(node : Tree, count : Int32?) : String?
      case node
      when Hash
        pick = count == 1 ? "one" : "other"
        node[pick]?.as?(String)
      when String
        node
      else
        nil
      end
    end

    # Основной вход. Зеркалит цепочку I18n-вызовов гема:
    #   Devise.t("user.signed_in", scope: "devise.sessions")
    #     → "devise.sessions.user.signed_in" → "devise.sessions.signed_in"
    #   Devise.t("errors.messages.not_saved", count: 3, resource: "User")
    # Интерполяция %{name} из opts (+ %{count}).
    def self.t(path : String, scope : String? = nil, count : Int32? = nil,
               **opts) : String?
      interp = {} of String => String
      opts.each { |k, v| interp[k.to_s] = v.to_s }
      translate(path, scope, count, interp)
    end

    def self.translate(path : String, scope : String?, count : Int32?,
                       interp : Hash(String, String)) : String?
      full = scope ? "#{scope}.#{path}" : path
      # ресурс-префикс фоллбек: "user.signed_in" → "signed_in",
      # "user_subject" → "subject" (default-цепочка I18n гема)
      fallback = if path.includes?('.')
                   path.split('.', 2)[1]
                 elsif path.ends_with?("_subject")
                   "subject"
                 end
      value = lookup_tree(full, count)
      value ||= fallback.try { |f| lookup_tree("#{scope}.#{f}", count) if scope }
      return nil unless value
      interp = interp.dup
      interp["count"] = count.to_s if count
      interp.reduce(value) { |acc, (k, v)| acc.gsub("%{#{k}}", v) }
    end

    private def self.lookup_tree(full : String, count : Int32?) : String?
      if (tree = current)
        node, present = dig(tree, full)
        # Ключ есть, но значение nil — как missing у ruby-I18n:
        # en-фоллбэк не делается (словарь не должен молча подменять
        # незаполненные ключи английским).
        return pick_string(node, count) if present
      end
      # Фоллбэк на en только когда ключа в текущей локали нет вовсе.
      node, _ = dig(en, full)
      pick_string(node, count)
    end
  end

  # Строгий вариант для словарных ключей (en запечён — промах это баг
  # интеграции, а не рантайм-условие).
  def self.t!(path : String, scope : String? = nil, count : Int32? = nil,
             **opts) : String
    interp = {} of String => String
    opts.each { |k, v| interp[k.to_s] = v.to_s }
    I18n.translate(path, scope, count, interp).not_nil!
  end

  # I18n.t гема в терминах порта.
  def self.t(path : String, scope : String? = nil, count : Int32? = nil,
             **opts) : String?
    interp = {} of String => String
    opts.each { |k, v| interp[k.to_s] = v.to_s }
    I18n.translate(path, scope, count, interp)
  end

  # I18n.locale / I18n.load_locale гема.
  def self.locale : String
    I18n.locale
  end

  def self.locale=(loc : String) : String
    I18n.locale = loc
  end

  def self.load_locale(path : String) : Nil
    I18n.load_locale(path)
  end
end
