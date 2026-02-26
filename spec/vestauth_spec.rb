# frozen_string_literal: true

RSpec.describe Vestauth do
  it "has a version number" do
    expect(Vestauth::VERSION).not_to be nil
  end

  it "exposes namespaced tool/provider and agent modules" do
    expect(Vestauth::Tool).to eq(Vestauth::Provider)
    expect(Vestauth.tool).to eq(Vestauth::Tool)
    expect(Vestauth.provider).to eq(Vestauth::Tool)
    expect(Vestauth.agent).to eq(Vestauth::Agent)
    expect(Vestauth.binary).to eq(Vestauth::Binary)
  end

  it "delegates tool verify to binary provider_verify" do
    binary = instance_double(Vestauth::Binary)
    allow(Vestauth::Binary).to receive(:new).and_return(binary)
    allow(binary).to receive(:provider_verify).and_return({ "uid" => "agent-123" })

    result = Vestauth.tool.verify(
      http_method: "GET",
      uri: "https://api.vestauth.com/whoami",
      headers: {
        "Signature" => "sig1=:abc:",
        "signature-input" => "sig1=(\"@method\");keyid=\"kid-1\"",
        "Signature-Agent" => "sig1=agent-123.agents.vestauth.com"
      }
    )

    expect(binary).to have_received(:provider_verify).with(
      http_method: "GET",
      uri: "https://api.vestauth.com/whoami",
      signature: "sig1=:abc:",
      signature_input: "sig1=(\"@method\");keyid=\"kid-1\"",
      signature_agent: "sig1=agent-123.agents.vestauth.com"
    )
    expect(result).to eq({ "uid" => "agent-123" })
  end

  it "passes through missing headers and lets binary verify fail if needed" do
    binary = instance_double(Vestauth::Binary)
    allow(Vestauth::Binary).to receive(:new).and_return(binary)
    allow(binary).to receive(:provider_verify).and_return({ "success" => false })

    Vestauth.tool.verify(
      http_method: "GET",
      uri: "https://api.vestauth.com/whoami",
      headers: {}
    )

    expect(binary).to have_received(:provider_verify).with(
      http_method: "GET",
      uri: "https://api.vestauth.com/whoami",
      signature: nil,
      signature_input: nil,
      signature_agent: nil
    )
  end
end
