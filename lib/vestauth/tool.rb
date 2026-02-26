# frozen_string_literal: true

module Vestauth
  module Tool
    module_function

    def verify(http_method:, uri:, headers:)
      signature = signature_header(headers)
      signature_input = signature_input_header(headers)
      signature_agent = signature_agent_header(headers)

      attrs = {
        http_method: http_method,
        uri: uri,
        signature: signature,
        signature_input: signature_input,
        signature_agent: signature_agent
      }
      vestauth_binary.provider_verify(**attrs)
    end

    def vestauth_binary
      Vestauth::Binary.new
    end
    private_class_method :vestauth_binary

    def signature_header(headers)
      headers["Signature"] || headers["signature"]
    end
    private_class_method :signature_header

    def signature_input_header(headers)
      headers["Signature-Input"] || headers["signature-input"]
    end
    private_class_method :signature_input_header

    def signature_agent_header(headers)
      headers["Signature-Agent"] || headers["signature-agent"]
    end
    private_class_method :signature_agent_header
  end
end
