# Sessions — the Warden replacement for P0: a cookie/session store
# keyed by "<scope>_id" plus the devise flash messages (en.yml strings).
# HTTP integration (action_pack cookie session) plugs on top; covered by
# unit specs like the action_mailer SMTP client.

module Devise
  class Session
    property flash : Hash(String, String)

    @data = {} of String => String

    def initialize(@flash = {} of String => String)
    end

    def sign_in(user : ActiveRecord::Base, scope : String = "user") : Nil
      @data["#{scope}_id"] = user.id.not_nil!.to_s
      @flash["notice"] = Devise.t!("#{scope}.signed_in", scope: "devise.sessions")
    end

    def sign_out(scope : String = "user") : Nil
      @data.delete("#{scope}_id")
      @flash["notice"] = Devise.t!("#{scope}.signed_out", scope: "devise.sessions")
    end

    def signed_in?(scope : String = "user") : Bool
      @data.has_key?("#{scope}_id")
    end

    def current_user(user_class : ActiveRecord::Base.class, scope : String = "user") : ActiveRecord::Base?
      if (id = @data["#{scope}_id"]?)
        user_class.find?(id.to_i64)
      end
    end

    # authenticate_user! equivalent: returns the user or yields the
    # failure path.
    def authenticate(user_class : ActiveRecord::Base.class, scope : String = "user")
      if user = current_user(user_class, scope)
        user
      else
        @flash["alert"] = Devise.t!("#{scope}.unauthenticated", scope: "devise.failure")
        yield
        nil
      end
    end
  end
end
