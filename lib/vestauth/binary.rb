# frozen_string_literal: true

require "json"
require "open3"
require "shellwords"

module Vestauth
  class Binary
    def initialize(executable: "vestauth")
      @executable = executable
    end

    def provider_verify(http_method:, uri:, signature:, signature_input:, signature_agent:)
      command = [
        @executable,
        "provider",
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

    private

    def run_json_command(command_args)
      command = command_args.map { |arg| Shellwords.escape(arg.to_s) }.join(" ")
      stdout, stderr, status = Open3.capture3(command)

      raise Vestauth::Error, (stderr.to_s.strip.empty? ? stdout : stderr) unless status.success?

      JSON.parse(stdout)
    end
  end
end
