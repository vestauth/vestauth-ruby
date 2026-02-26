# frozen_string_literal: true

module Vestauth
  module Agent
    module_function

    def headers(http_method:, uri:, private_jwk:, id:)
      vestauth_binary.agent_headers(
        http_method: http_method,
        uri: uri,
        private_jwk: private_jwk,
        id: id
      )
    end

    def vestauth_binary
      Vestauth::Binary.new
    end
    private_class_method :vestauth_binary
  end
end
