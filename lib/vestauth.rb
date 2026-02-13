# frozen_string_literal: true

require_relative "vestauth/version"
require_relative "vestauth/agent"
require_relative "vestauth/binary"
require_relative "vestauth/provider"

module Vestauth
  class Error < StandardError; end

  def self.provider
    Provider
  end

  def self.agent
    Agent
  end

  def self.binary
    Binary
  end
end
