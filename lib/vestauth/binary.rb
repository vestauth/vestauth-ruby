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

    def agent_headers(http_method:, uri:, private_key:, id:)
      private_jwk = serialize_json_arg(private_key, name: "private_key")

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

    def primitives_verify(http_method:, uri:, signature_header:, signature_input_header:, public_key:)
      public_jwk = serialize_json_arg(public_key, name: "public_key")

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

    def serialize_json_arg(value, name:)
      return value if value.is_a?(String)
      return JSON.generate(value) if value.is_a?(Hash) || value.is_a?(Array)
      return JSON.generate(value.to_h) if value.respond_to?(:to_h)
      return JSON.generate(value.as_json) if value.respond_to?(:as_json)

      raise ArgumentError, "#{name} must be a JSON string, Hash/Array, or object responding to #to_h"
    end
  end
end
