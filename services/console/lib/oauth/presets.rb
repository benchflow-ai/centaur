module Oauth
  # One-click Integrations cards an admin uses to register an OAuth app.
  #
  # A preset supplies the app's attributes (#preset) and its OAuth client
  # registration endpoint. A provider-backed preset is a provider strategy that
  # defines both (Mercator); a standalone preset (Runlayer) configures a generic
  # provider, such as custom, from what the admin enters (#setup_from). Unlike
  # providers, presets add no runtime behavior: once the app exists it is an
  # ordinary OauthApp.
  module Presets
    def self.registry
      @registry ||= { Runlayer::KEY => Runlayer.new }.freeze
    end

    # Every preset, standalone and provider-backed.
    def self.all
      providers = Oauth::Providers.registry.values.select { |provider| provider_preset?(provider) }
      (registry.values + providers).sort_by(&:key)
    end

    def self.fetch(key)
      registry[key] || Oauth::Providers.fetch(key).then { |provider| provider if provider_preset?(provider) }
    end

    def self.provider_preset?(provider)
      provider.respond_to?(:preset) && provider.respond_to?(:registration_endpoint)
    end
  end
end
