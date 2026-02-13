# vestauth-ruby

```
bundle install vestauth
```

```
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  before_action :verify_agent!
  helper_method :current_agent

  private

  def verify_agent!
    @current_agent ||= Vestauth.provider.verify(http_method: request.method, uri: request.original_url, headers: request.headers)
  rescue => e
    render json: { error: { status: 401, code: 401, message: e.message } }, status: 401
  end

  def current_agent
    @current_agent
  end
end
```

## Development

```
bundle exec rubocop -A
bundle exec bump patch --tag --tag-prefix v
git push origin main --tags
```

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
