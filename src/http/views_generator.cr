# `crails g devise:views` — копирует встроенные ERB-вьюхи devise в
# app/views/devise/** (после этого приложение кастомизирует формы).
# Формат вывода — thor-строки генераторов railties ("      create ...").
#
# Вызов: Devise::ViewsGenerator.run(argv) — рантайм-реестра генераторов
# у railties нет, CLI-хук подключается приложением (см. PLAN.md) или
# файлы просто копируются этой командой напрямую.

require "file_utils"

module Devise
  class ViewsGenerator
    SESSIONS_NEW = <<-HTML
    <h2>Log in</h2>
    <%= flash["alert"] ? "<p class=\\"alert alert-danger\\">#{flash["alert"]}</p>" : "" %>
    <%= flash["notice"] ? "<p class=\\"alert alert-info\\">#{flash["notice"]}</p>" : "" %>
    <form method="post" action="<%= __devise_mapping.path_prefix %>/sign_in">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= nested_param("user", "email") %>">
      <label for="user_password">Password</label>
      <input type="password" name="user[password]" id="user_password">
      <label for="user_remember_me"><input type="checkbox" value="1" name="user[remember_me]" id="user_remember_me"> Remember me</label>
      <button type="submit">Log in</button>
    </form>
    HTML

    REGISTRATIONS_NEW = <<-HTML
    <h2>Sign up</h2>
    <%= resource && !resource.errors.empty? ? "<div class=\\"alert alert-danger\\"><ul>#{resource.errors.full_messages.map { |m| "<li>#{m}</li>" }.join}</ul></div>" : "" %>
    <form method="post" action="<%= __devise_mapping.path_prefix %>">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= nested_param("user", "email") %>">
      <label for="user_password">Password</label>
      <input type="password" name="user[password]" id="user_password">
      <label for="user_password_confirmation">Password Confirmation</label>
      <input type="password" name="user[password_confirmation]" id="user_password_confirmation">
      <button type="submit">Sign up</button>
    </form>
    HTML

    REGISTRATIONS_EDIT = <<-HTML
    <h2>Edit <%= resource_class %></h2>
    <form method="post" action="<%= __devise_mapping.path_prefix %>">
      <input type="hidden" name="_method" value="patch">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= current_user.try(&.attributes["email"]).try(&.to_s) %>">
      <label for="user_password">Password</label>
      <input type="password" name="user[password]" id="user_password"> <i>(leave blank if you don't want to change it)</i>
      <label for="user_password_confirmation">Password Confirmation</label>
      <input type="password" name="user[password_confirmation]" id="user_password_confirmation">
      <label for="user_current_password">Current Password</label>
      <input type="password" name="user[current_password]" id="user_current_password"> <i>(we need your current password to confirm your changes)</i>
      <button type="submit">Update</button>
    </form>
    HTML

    PASSWORDS_NEW = <<-HTML
    <h2>Forgot your password?</h2>
    <form method="post" action="<%= __devise_mapping.path_prefix %>/password">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= nested_param("user", "email") %>">
      <button type="submit">Send me reset password instructions</button>
    </form>
    HTML

    PASSWORDS_EDIT = <<-HTML
    <h2>Change your password</h2>
    <form method="post" action="<%= __devise_mapping.path_prefix %>/password">
      <input type="hidden" name="_method" value="patch">
      <input type="hidden" name="user[reset_password_token]" value="<%= params["reset_password_token"] %>">
      <label for="user_password">New Password</label>
      <input type="password" name="user[password]" id="user_password">
      <label for="user_password_confirmation">Confirm New Password</label>
      <input type="password" name="user[password_confirmation]" id="user_password_confirmation">
      <button type="submit">Change my password</button>
    </form>
    HTML

    CONFIRMATIONS_NEW = <<-HTML
    <h2>Resend confirmation instructions</h2>
    <form method="post" action="<%= __devise_mapping.path_prefix %>/confirmation">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= nested_param("user", "email") %>">
      <button type="submit">Resend confirmation instructions</button>
    </form>
    HTML

    UNLOCKS_NEW = <<-HTML
    <h2>Resend unlock instructions</h2>
    <form method="post" action="<%= __devise_mapping.path_prefix %>/unlock">
      <label for="user_email">Email</label>
      <input type="email" name="user[email]" id="user_email" value="<%= nested_param("user", "email") %>">
      <button type="submit">Resend unlock instructions</button>
    </form>
    HTML

    VIEWS = {
      "sessions/new"      => SESSIONS_NEW,
      "registrations/new" => REGISTRATIONS_NEW,
      "registrations/edit" => REGISTRATIONS_EDIT,
      "passwords/new"     => PASSWORDS_NEW,
      "passwords/edit"    => PASSWORDS_EDIT,
      "confirmations/new" => CONFIRMATIONS_NEW,
      "unlocks/new"       => UNLOCKS_NEW,
    }

    def self.run(argv : Array(String) = [] of String) : Nil
      force = argv.any? { |a| {"-f", "--force"}.includes?(a) }
      quiet = argv.any? { |a| {"-q", "--quiet"}.includes?(a) }
      new(force, quiet).generate
    end

    def initialize(@force : Bool, @quiet : Bool)
    end

    def generate : Nil
      VIEWS.each do |path, content|
        write("app/views/devise/#{path}.html.erb", content)
      end
    end

    private def write(path : String, content : String) : Nil
      if File.exists?(path) && !@force
        say("identical", path)
        return
      end
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content)
      say("create", path)
    end

    private def say(status : String, path : String) : Nil
      return if @quiet
      puts status.rjust(12) + "  " + path
    end
  end
end
