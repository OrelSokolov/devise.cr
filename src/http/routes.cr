# `devise_for :users` в CRails::Routes::Drawer — стандартная таблица
# роутов devise 4.9.4 (снята оракулом oracle/http_expected.yml, кейсы
# http_route_*): модули берутся из модели (`devise`-макрос), имена/глаголы/
# пути — 1:1 с гемом. Роуты добавляются в позицию вызова (как в Rails).

class CRails::Routes::Drawer
  def devise_for(resource : String | Symbol, **opts) : Nil
    mapping = Devise.mapping(resource)
    raise ArgumentError.new(
      "devise_for :#{resource}: devise-модель не найдена (нет класса с макросом `devise` для скопа :#{resource.to_s.singularize})"
    ) unless mapping
    modules = mapping.modules
    prefix = mapping.path_prefix # "/users"
    scope = mapping.scope        # "user"

    if modules.includes?(:database_authenticatable) || modules.includes?(:token_authenticatable)
      get "#{prefix}/sign_in", to: "devise/sessions#new", as: "new_#{scope}_session"
      post "#{prefix}/sign_in", to: "devise/sessions#create", as: "#{scope}_session"
      delete "#{prefix}/sign_out", to: "devise/sessions#destroy", as: "destroy_#{scope}_session"
    end

    if modules.includes?(:registerable)
      get "#{prefix}/cancel", to: "devise/registrations#cancel", as: "cancel_#{scope}_registration"
      get "#{prefix}/sign_up", to: "devise/registrations#new", as: "new_#{scope}_registration"
      get "#{prefix}/edit", to: "devise/registrations#edit", as: "edit_#{scope}_registration"
      patch "#{prefix}", to: "devise/registrations#update", as: "#{scope}_registration"
      put "#{prefix}", to: "devise/registrations#update"
      delete "#{prefix}", to: "devise/registrations#destroy"
      post "#{prefix}", to: "devise/registrations#create"
    end

    if modules.includes?(:recoverable)
      get "#{prefix}/password/new", to: "devise/passwords#new", as: "new_#{scope}_password"
      get "#{prefix}/password/edit", to: "devise/passwords#edit", as: "edit_#{scope}_password"
      patch "#{prefix}/password", to: "devise/passwords#update", as: "#{scope}_password"
      put "#{prefix}/password", to: "devise/passwords#update"
      post "#{prefix}/password", to: "devise/passwords#create"
    end

    if modules.includes?(:confirmable)
      get "#{prefix}/confirmation/new", to: "devise/confirmations#new", as: "new_#{scope}_confirmation"
      get "#{prefix}/confirmation", to: "devise/confirmations#show", as: "#{scope}_confirmation"
      post "#{prefix}/confirmation", to: "devise/confirmations#create"
    end

    # Отклонение от гема: unlock-роуты рисуются при любом lockable
    # (unlock_strategy — рантайм-конфиг модели, в дефолте :both, email
    # входит; гем не рисует их только при unlock_strategy = :none/:time).
    if modules.includes?(:lockable)
      get "#{prefix}/unlock/new", to: "devise/unlocks#new", as: "new_#{scope}_unlock"
      get "#{prefix}/unlock", to: "devise/unlocks#show", as: "#{scope}_unlock"
      post "#{prefix}/unlock", to: "devise/unlocks#create"
    end

    if modules.includes?(:omniauthable)
      mapping.providers.each do |provider|
        get "#{prefix}/auth/#{provider}", to: "devise/omniauth_callbacks#passthru",
          as: "#{scope}_#{provider}_omniauth_authorize"
        post "#{prefix}/auth/#{provider}", to: "devise/omniauth_callbacks#passthru"
        get "#{prefix}/auth/#{provider}/callback", to: "devise/omniauth_callbacks##{provider}",
          as: "#{scope}_#{provider}_omniauth_callback"
        post "#{prefix}/auth/#{provider}/callback", to: "devise/omniauth_callbacks##{provider}"
      end
    end
  end
end
