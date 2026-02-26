# frozen_string_literal: true

RSpec.describe Vestauth::Binary do
  describe "#tool_verify" do
    it "calls vestauth provider verify and parses json output" do
      status = instance_double(Process::Status, success?: true)
      binary = described_class.new

      expect(Open3).to receive(:capture3).with(
        include("vestauth provider verify GET https://api.vestauth.com/whoami")
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
end
