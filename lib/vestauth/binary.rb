# frozen_string_literal: true

require "json"
require "open3"

module Vestauth
  class Binary
    def initialize(executable: "vestauth")
      @executable = executable
    end

    def tool_verify(http_method:, uri:, signature:, signature_input:, signature_agent:)
      command = [
        @executable,
        "tool",
        "verify",
        http_method,
        uri,
        "--signature",
        signature,
        "--signature-input",
        signature_input,
        "--signature-agent",
        signature_agent
      ]

      run_json_command(command)
    end

    def agent_headers(http_method:, uri:, private_jwk:, id:)
      private_jwk = private_jwk.as_json.to_json

      command = [
        @executable,
        "agent",
        "headers",
        http_method,
        uri,
        "--private-jwk",
        private_jwk,
        "--uid",
        id
      ]

      run_json_command(command)
    end

    def primitives_verify(http_method:, uri:, signature_header:, signature_input_header:, public_jwk:)
      public_jwk = public_jwk.as_json.to_json

      command = [
        @executable,
        "primitives",
        "verify",
        http_method,
        uri,
        "--signature",
        signature_header,
        "--signature-input",
        signature_input_header,
        "--public-jwk",
        public_jwk
      ]

      run_json_command(command)
    end

    private

    def run_json_command(command_args)
      argv = command_args.map { |arg| arg.nil? ? "" : arg.to_s }
      stdout, stderr, status = Open3.capture3(*argv)

      raise Vestauth::Error, (stderr.to_s.strip.empty? ? stdout : stderr) unless status.success?

      JSON.parse(stdout)
    end
  end
end
