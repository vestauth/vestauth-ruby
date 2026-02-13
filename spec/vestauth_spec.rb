# frozen_string_literal: true

RSpec.describe Vestauth do
  it "has a version number" do
    expect(Vestauth::VERSION).not_to be nil
  end

  it "exposes namespaced provider and agent modules" do
    expect(Vestauth.provider).to eq(Vestauth::Provider)
    expect(Vestauth.agent).to eq(Vestauth::Agent)
  end

  it "raises a not-yet-implemented error for provider verify" do
    expect do
      Vestauth.provider.verify("get", "https://example.com", {})
    end.to raise_error(Vestauth::Error, "implement")
  end
end
