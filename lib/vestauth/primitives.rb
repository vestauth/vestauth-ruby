# frozen_string_literal: true

module Vestauth
  module Primitives
    module_function

    def verify(http_method:, uri:, signature_header:, signature_input_header:, public_jwk:)
      vestauth_binary.primitives_verify(
        http_method: http_method,
        uri: uri,
        signature_header: signature_header,
        signature_input_header: signature_input_header,
        public_jwk: public_jwk
      )
    end

    def vestauth_binary
      Vestauth::Binary.new
    end
    private_class_method :vestauth_binary
  end
end
