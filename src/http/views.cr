# Встроенные минимальные devise-вьюхи: рендерятся контроллерами, когда
# в приложении нет app/views/devise/** (генерируются командой
# Devise::ViewsGenerator.run — `crails g devise:views`, см. ниже).
# Формы используют реальные пути роутов devise (по mapping скопа).

module Devise
  module Views
    private def self.controller_name_action(controller : ActionController::Base, action : String) : String
      name = controller.class.name.split("::").last.underscore.gsub(/_controller$/, "")
      "\#{name}/\#{action}"
    end

    def self.fallback(action : String, controller : ActionController::Base) : String
      mapping = controller.__devise_mapping
      prefix = mapping.path_prefix
      flash = String.build do |io|
        if (alert = controller.flash["alert"]?)
          io << %(<p class="alert alert-danger">) << escape_html(alert) << "</p>"
        end
        if (notice = controller.flash["notice"]?)
          io << %(<p class="alert alert-info">) << escape_html(notice) << "</p>"
        end
      end
      errors = resource_errors(controller)
      email = controller.nested_param("user", "email") || ""

      body = case controller_name_action(controller, action)
      when "sessions/new"
        form(action: "#{prefix}/sign_in") do |f|
          f << email_field(email) << password_field("password")
          f << checkbox("remember_me") if mapping.modules.includes?(:rememberable)
          f << %(<button type="submit">Log in</button>)
        end
      when "registrations/new"
        form(action: prefix) do |f|
          f << email_field(email) << password_field("password")
          f << password_field("password_confirmation")
          f << %(<button type="submit">Sign up</button>)
        end
      when "registrations/edit"
        form(action: prefix, method: "patch") do |f|

          f << password_field("password") << password_field("password_confirmation")
          f << password_field("current_password")
          f << %(<button type="submit">Update</button>)
        end
      when "passwords/new"
        form(action: "#{prefix}/password") do |f|
          f << email_field(email)
          f << %(<button type="submit">Send me reset password instructions</button>)
        end
      when "passwords/edit"
        token = controller.params["reset_password_token"]?.try(&.to_s) ||
                controller.nested_param("user", "reset_password_token") || ""
        form(action: "#{prefix}/password", method: "patch") do |f|
          f << %(<input type="hidden" name="user[reset_password_token]" value=") << escape_html(token) << "\">"
          f << password_field("password") << password_field("password_confirmation")
          f << %(<button type="submit">Change my password</button>)
        end
      when "confirmations/new"
        form(action: "#{prefix}/confirmation") do |f|
          f << email_field(email)
          f << %(<button type="submit">Resend confirmation instructions</button>)
        end
      when "unlocks/new"
        form(action: "#{prefix}/unlock") do |f|
          f << email_field(email)
          f << %(<button type="submit">Resend unlock instructions</button>)
        end
      else
        ""
      end

      String.build do |io|
        io << "<!doctype html><html><head><meta charset=\"utf-8\">"
        io << "<title>Devise</title></head><body>"
        io << flash << errors << body << "</body></html>"
      end
    end

    private def self.resource_errors(controller : ActionController::Base) : String
      resource = controller.responds_to?(:resource) ? controller.resource : nil
      return "" unless resource && !resource.errors.empty?
      String.build do |io|
        io << %(<div class="alert alert-danger"><ul>)
        resource.errors.full_messages.each do |msg|
          io << "<li>" << escape_html(msg) << "</li>"
        end
        io << "</ul></div>"
      end
    end

    private def self.form(action : String, method : String = "post",
                          & : Array(String) ->) : String
      html_method = method == "post" ? "" : %(<input type="hidden" name="_method" value="#{method}">)
      parts = [] of String
      yield parts
      %(<form method="post" action="#{action}">#{html_method}#{parts.join}</form>)
    end

    private def self.email_field(value : String) : String
      %(<label for="user_email">Email</label>) +
        %(<input type="email" name="user[email]" id="user_email" value="#{escape_html(value)}">)
    end

    private def self.password_field(name : String) : String
      label = name.split("_").map(&.capitalize).join(" ")
      %(<label for="user_#{name}">#{label}</label>) +
        %(<input type="password" name="user[#{name}]" id="user_#{name}">)
    end

    private def self.checkbox(name : String) : String
      %(<label for="user_#{name}"><input type="checkbox" value="1" ) +
        %(name="user[#{name}]" id="user_#{name}"> Remember me</label>)
    end

    private def self.escape_html(s : String) : String
      s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
        .gsub('"', "&quot;").gsub("'", "&#39;")
    end
  end
end
