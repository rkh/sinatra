require 'sinatra/base'
require 'uri'

module Sinatra
  class Request
    SAFE_METHODS = %w[GET HEAD OPTIONS TRACE]

    def safe?
      SAFE_METHODS.include? request_method
    end
  end

  class CsrfProtection
    def initialize(app, base = Sinatra::Base)
      @app, @base = app, base
    end

    def call(env)
      r = Sinatra::Request.new env
      if r.safe? or !r.referrer or URI.parse(r.referrer).host == r.host
        @app.call env
      else
        response
      end
    end

    def response
      error = 'Potentinal CSRF attack prevented!'
      fail error if @base.test?
      response = Rack::Response.new
      response.status = 412
      if @base.development?
        response['Content-Type'] = 'text/html'
        response.body << <<-HTML.gsub(/^ {10}/, '')
          <!DOCTYPE html>
          <html>
            <head>
              <style type="text/css">
              body { text-align:center;font-family:helvetica,arial;font-size:22px;
                color:#888;margin:20px}
              #c {margin:0 auto;width:500px;text-align:left}
              </style>
            </head>
            <body>
              <h2>#{error}</h2>
              <img src='/__sinatra__/500.png'>
              <div id="c">
                <p>
                  Sinatra automatically blocks unsafe requests coming from other
                  hosts. If you want to allow such requests, please make sure
                  you fully understand how CSRF attacks work first, and then,
                  add the following line to your Sinatra application:
                </p>
                <pre>disable :csrf_protection</pre>
              </div>
            </body>
          </html>
        HTML
      else
        response['Content-Type'] = 'text/plain'
        response.body << error
      end
      response.finish
    end
  end
end
