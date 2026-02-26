# frozen_string_literal: true

require_relative "vestauth/version"
require_relative "vestauth/agent"
require_relative "vestauth/binary"
require_relative "vestauth/primitives"
require_relative "vestauth/tool"
require_relative "vestauth/provider"

module Vestauth
  class Error < StandardError; end

  def self.agent
    Agent
  end
  
  def self.tool
    Tool
  end

  class << self
    alias provider tool
  end

  def self.primitives
    Primitives
  end

  def self.binary
    Binary
  end
end
