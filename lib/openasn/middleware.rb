# frozen_string_literal: true

module OpenASN
  # Rack middleware: classifies the request IP once and exposes the result
  # at env["openasn.result"] (nil when the IP is missing/unparseable —
  # never raises into the request cycle).
  #
  #   use OpenASN::Middleware
  #   # then anywhere downstream:
  #   request.env["openasn.result"]&.infrastructure?
  #
  # THE CLASSIC INTEGRATION BUG (read this before filing "everything is
  # :private/:hosting"): if your app sits behind a proxy/load balancer and
  # trusted proxies aren't configured, the IP you classify is your own
  # infrastructure's. Inside Rails we use ActionDispatch's remote_ip
  # (which honors config.action_dispatch.trusted_proxies); bare Rack falls
  # back to REMOTE_ADDR. Behind Cloudflare or a CDN, make sure the real
  # client IP reaches Rails (e.g. cloudflare-rails gem or equivalent
  # trusted_proxies setup) BEFORE trusting these verdicts.
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      env["openasn.result"] = classify(env)
      @app.call(env)
    end

    private

    def classify(env)
      ip = if defined?(ActionDispatch::Request)
             ActionDispatch::Request.new(env).remote_ip
           else
             env["REMOTE_ADDR"]
           end
      return nil if ip.nil? || ip.empty?

      OpenASN.lookup(ip)
    rescue InvalidIPError
      nil
    rescue StandardError => e
      # Never let classification break a request; log and move on.
      OpenASN.configuration.logger.warn("openasn middleware: #{e.class}: #{e.message}")
      nil
    end
  end
end
