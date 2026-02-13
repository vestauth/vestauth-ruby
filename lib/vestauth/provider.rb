# frozen_string_literal: true

module Vestauth
  module Provider
    module_function

    def verify(_method, _url, _headers = {})
      raise Vestauth::Error, "implement"
    end
  end
end
