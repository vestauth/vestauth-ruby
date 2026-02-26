# frozen_string_literal: true

RSpec.describe Vestauth::Binary do
  describe "#tool_verify" do
    it "calls vestauth tool verify and parses json output" do
      status = instance_double(Process::Status, success?: true)
      binary = described_class.new

      expect(Open3).to receive(:capture3).with(
        "vestauth",
        "tool",
        "verify",
        "GET",
        "https://api.vestauth.com/whoami",
        "--signature",
        "sig1=:abc:",
        "--signature-input",
        "sig1=(\"@method\");keyid=\"kid-1\"",
        "--signature-agent",
        "sig1=agent-123.agents.vestauth.com"
      ).and_return(['{"uid":"agent-123"}', "", status])

      result = binary.tool_verify(
        http_method: "GET",
        uri: "https://api.vestauth.com/whoami",
        signature: "sig1=:abc:",
        signature_input: "sig1=(\"@method\");keyid=\"kid-1\"",
        signature_agent: "sig1=agent-123.agents.vestauth.com"
      )

      expect(result).to eq({ "uid" => "agent-123" })
    end

    it "raises Vestauth::Error on command failure" do
      status = instance_double(Process::Status, success?: false)
      binary = described_class.new

      allow(Open3).to receive(:capture3).and_return(["", "bad signature", status])

      expect do
        binary.tool_verify(
          http_method: "GET",
          uri: "https://api.vestauth.com/whoami",
          signature: "sig1=:abc:",
          signature_input: "sig1=(\"@method\");keyid=\"kid-1\"",
          signature_agent: "sig1=agent-123.agents.vestauth.com"
        )
      end.to raise_error(Vestauth::Error, "bad signature")
    end
  end

  describe "#agent_headers" do
    it "serializes a private jwk via as_json" do
      status = instance_double(Process::Status, success?: true)
      binary = described_class.new
      private_jwk = instance_double("PrivateJwk", as_json: { "kty" => "EC" })

      expect(Open3).to receive(:capture3).with(
        "vestauth",
        "agent",
        "headers",
        "GET",
        "https://api.vestauth.com/whoami",
        "--private-jwk",
        '{"kty":"EC"}',
        "--uid",
        "agent-123"
      ).and_return(['{"Signature":"sig1=:abc:"}', "", status])

      result = binary.agent_headers(
        http_method: "GET",
        uri: "https://api.vestauth.com/whoami",
        private_jwk: private_jwk,
        id: "agent-123"
      )

      expect(result).to eq({ "Signature" => "sig1=:abc:" })
    end
  end

  describe "#primitives_verify" do
    it "serializes a public jwk via as_json" do
      status = instance_double(Process::Status, success?: true)
      binary = described_class.new
      public_jwk = instance_double("PublicJwk", as_json: { "kty" => "EC" })

      expect(Open3).to receive(:capture3).with(
        "vestauth",
        "primitives",
        "verify",
        "GET",
        "https://api.vestauth.com/whoami",
        "--signature",
        "sig1=:abc:",
        "--signature-input",
        "sig1=(\"@method\");keyid=\"kid-1\"",
        "--public-jwk",
        '{"kty":"EC"}'
      ).and_return(['{"success":true}', "", status])

      result = binary.primitives_verify(
        http_method: "GET",
        uri: "https://api.vestauth.com/whoami",
        signature_header: "sig1=:abc:",
        signature_input_header: "sig1=(\"@method\");keyid=\"kid-1\"",
        public_jwk: public_jwk
      )

      expect(result).to eq({ "success" => true })
    end
  end
end
