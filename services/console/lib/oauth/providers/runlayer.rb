require "uri"

module Oauth
  module Providers
    # Runlayer's user OAuth client for the unified Plugin protected resource.
    # Credentials belong to the authenticated Console user. MCP OAuth does not
    # promise OIDC/userinfo, so we neither decode access tokens nor infer an
    # external account from email. Reconnecting replaces this owner's grant.
    #
    # The tenant's MCP URL is the app's provider_config "resource". It is fixed
    # once the app exists, so every credential the app mints is bound to it, and
    # the authorization, token, registration and revocation endpoints are the
    # same-origin /api/v1/oauth/* paths. token-broker refreshes with the same
    # resource indicator, read from provider_config.
    class Runlayer
      KEY = "runlayer"
      SCOPE = "mcp:proxy"
      CONFIG_KEYS = %w[resource].freeze
      URL_MESSAGE = "resource must be an exact HTTPS Runlayer MCP URL ending in /mcp".freeze

      # Validation messages for a provider_config hash; empty when valid.
      def self.config_errors(config)
        unknown = config.keys - CONFIG_KEYS
        errors = unknown.any? ? [ "has unknown keys: #{unknown.join(', ')}" ] : []
        errors << URL_MESSAGE unless resource_uri(config["resource"])
        errors
      end

      # The parsed resource URL, or nil unless it is an exact HTTPS MCP URL.
      def self.resource_uri(raw)
        return nil unless raw.is_a?(String) && raw.present? && raw == raw.strip

        uri = URI.parse(raw)
        return nil unless uri.is_a?(URI::HTTPS) && uri.host.present? && uri.port == 443 &&
          uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil? && uri.path.end_with?("/mcp") &&
          !raw.match?(/[*\[\]{}]/)

        uri
      rescue URI::InvalidURIError
        nil
      end

      # Built per app from provider_config; the registry's unconfigured
      # instance only names the provider and drives the admin preset.
      def initialize(app = nil, config: nil)
        @config = config || app&.provider_config || {}
      end

      def key = KEY
      def display_name = "Runlayer"
      def configured? = resource_uri.present?
      def resource_url = configured? ? @config["resource"] : nil
      def authorization_endpoint = endpoint("authorize")
      def token_endpoint = endpoint("token")
      def registration_endpoint = endpoint("register")
      def revocation_endpoint = endpoint("revoke")
      def token_endpoint_auth_method = "client_secret_post"
      def identity_scopes = []
      def required_scopes = [ SCOPE ]
      def authorization_scope_param = "scope"
      def scope_separator = " "
      def extra_authorization_params = { "resource" => resource_url }
      def extra_token_params = { "resource" => resource_url }
      def refreshable? = true
      def parse_granted_scopes(scope) = scope.to_s.split
      def refresh_scopes(scopes) = Array(scopes)
      def consent_context = resource_url
      def api_hosts = [ resource_uri!.host ]

      def credential_request_rules
        [ { host: resource_uri!.host, http_methods: %w[GET POST DELETE], paths: [ resource_uri!.path ] } ]
      end

      def preset
        { slug: KEY, description: "Your Runlayer tools and permissions.",
          allowed_scopes: [ SCOPE ], shared: false, always_available: true }
      end

      # The admin enters the tenant's MCP URL when registering the preset.
      def preset_config(params) = { "resource" => params[:resource_url].to_s.strip }

      def identity_for_user(user)
        { subject: "owner-#{user.oid}", name: "Your Runlayer connection" }
      end

      def wrapping_secret_labels = { "centaur-tool" => KEY }

      def validate_result!(result)
        return if result.scope.blank? || parse_granted_scopes(result.scope).include?(SCOPE)

        raise Broker::ExchangeError.new("Runlayer scope was not granted", stage: "oauth", code: "missing_scope")
      end

      private

      def resource_uri = self.class.resource_uri(@config["resource"])

      def resource_uri!
        resource_uri || raise(Broker::ExchangeError.new(URL_MESSAGE, stage: "config"))
      end

      def endpoint(action)
        uri = resource_uri!.dup
        uri.path = "/api/v1/oauth/#{action}"
        uri.to_s
      end
    end
  end
end
