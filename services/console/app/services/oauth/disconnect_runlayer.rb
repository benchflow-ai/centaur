module Oauth
  # Disconnects a personal Runlayer connection. Local access is removed first,
  # under the credential's row lock (the lock token-broker and reconnect take),
  # so no refresh or proxy sync can use the tokens afterwards. Remote revocation
  # then runs outside the transaction so a slow revocation endpoint never holds
  # the lock. Returns whether every remote revocation succeeded.
  class DisconnectRunlayer
    def initialize(http: HttpClient.new(open_timeout: 5, read_timeout: 5))
      @http = http
    end

    def call(credential)
      tokens = nil
      credential.with_lock do
        tokens = [ [ credential.refresh_token, "refresh_token" ], [ credential.access_token, "access_token" ] ]
        credential.update!(access_token: nil, refresh_token: nil, expires_at: Time.current,
          dead: true, dead_reason: "disconnected", next_attempt_at: nil)
      end
      revoke(credential, tokens)
    end

    private

    def revoke(credential, tokens)
      provider = credential.oauth_app.provider_strategy
      tokens.reject { |token, _| token.blank? }.map do |token, hint|
        @http.post(provider.revocation_endpoint, form: {
          "client_id" => credential.effective_client_id,
          "client_secret" => credential.effective_client_secret,
          "token" => token,
          "token_type_hint" => hint
        }).success?
      end.all?
    rescue StandardError => e
      Rails.logger.warn { "runlayer_revocation_failed credential=#{credential.oid} error=#{e.class}" }
      false
    end
  end
end
