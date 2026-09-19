# frozen_string_literal: true

require "net/http"
require "uri"

module OpenASN
  # Minimal stdlib HTTP client for the updater and Tier B executor.
  #
  # * Always sends a descriptive User-Agent (some endpoints 403 UA-less
  #   clients; it's also basic politeness toward the volunteer-run sources
  #   this gem depends on).
  # * Follows redirects across hosts — GitHub release downloads ALWAYS
  #   redirect to objects.githubusercontent.com / release-assets.…; if your
  #   egress is allowlisted, those hosts must be on the list too.
  # * Follows them ONLY to http/https. Tier B sources are remote parties this
  #   project does not control; a `Location: file:///…` (or ftp:, data:, …)
  #   would otherwise turn a fetch into a local-file read on the host running
  #   the gem. Every hop, including the first URL, is scheme-checked.
  # * Supports conditional GET via ETag (returns :not_modified).
  # * Never talks to api.github.com (60 req/hr unauthenticated limit);
  #   releases/download/<tag>/ asset URLs redirect fine without auth.
  class HttpClient
    MAX_REDIRECTS = 5
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 120 # artifacts are ~6MB; Apple's relay CSV ~10MB
    ALLOWED_SCHEMES = %w[http https].freeze

    Response = Struct.new(:body, :etag, keyword_init: true)

    def initialize(user_agent:, logger:)
      @user_agent = user_agent
      @logger = logger
    end

    # -> Response | :not_modified. Raises on HTTP errors / timeouts.
    def get(url, etag: nil)
      headers = { "User-Agent" => @user_agent, "Accept-Encoding" => "identity" }
      headers["If-None-Match"] = etag if etag

      response = request(Net::HTTP::Get, url, headers, MAX_REDIRECTS)
      case response
      when Net::HTTPNotModified then :not_modified
      when Net::HTTPSuccess then Response.new(body: response.body, etag: response["etag"])
      else raise UpdateError, "HTTP #{response.code} for #{url}"
      end
    end

    def post_form(url, form)
      headers = { "User-Agent" => @user_agent,
                  "Accept-Encoding" => "identity",
                  "Content-Type" => "application/x-www-form-urlencoded" }
      response = request(Net::HTTP::Post, url, headers, MAX_REDIRECTS, URI.encode_www_form(form))
      case response
      when Net::HTTPSuccess then Response.new(body: response.body, etag: response["etag"])
      else raise UpdateError, "HTTP #{response.code} for #{url}"
      end
    end

    private

    def request(method, url, headers, redirects_left, body = nil)
      raise UpdateError, "too many redirects for #{url}" if redirects_left.zero?

      uri = http_uri!(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = OPEN_TIMEOUT
      http.read_timeout = READ_TIMEOUT

      request = method.new(uri, headers)
      request.body = body if body
      response = http.request(request)
      # Ruby models 304 Not Modified as a 3xx response, but it is not a
      # redirect and correctly has no Location header. Return it to #get so
      # conditional GETs are clean :not_modified events instead of noisy
      # keep-stale failures.
      if response.is_a?(Net::HTTPRedirection) && !response.is_a?(Net::HTTPNotModified)
        location = response["location"]
        raise UpdateError, "redirect without Location from #{url}" if location.nil?

        # Resolve relative AND absolute Locations through URI.join (an absolute
        # target simply replaces the base), then re-check the scheme: a remote
        # source must never be able to redirect us off http/https. Checking
        # only `start_with?("http")` let `file://`, `ftp://`, `data:` … through
        # to the next hop.
        target = redirect_target!(url, location)
        if uri.scheme == "https" && target.scheme == "http"
          @logger.warn("openasn: #{url} redirected to plaintext #{target} — downgraded transport")
        end
        # Conditional headers stay on the ORIGINAL url's cache identity;
        # redirect targets are one-off signed URLs. Keep method headers such
        # as Content-Type for POST-form provider endpoints.
        redirect_headers = headers.reject { |key, _| key.casecmp("If-None-Match").zero? }
        return request(method, target.to_s, redirect_headers, redirects_left - 1, body)
      end
      response
    end

    # Every URL this client dials — the caller's and every redirect hop — must
    # be an absolute http/https URL with a host. Anything else is refused
    # before a connection (or a local-file read) can happen.
    def http_uri!(url)
      uri = begin
        URI(url.to_s)
      rescue URI::Error => e
        raise UpdateError, "invalid URL #{url.inspect} (#{e.message})"
      end
      unless ALLOWED_SCHEMES.include?(uri.scheme)
        raise UpdateError, "refusing non-http(s) URL #{url.inspect} (scheme #{uri.scheme.inspect})"
      end
      raise UpdateError, "refusing URL without a host: #{url.inspect}" if uri.host.nil? || uri.host.empty?

      uri
    end

    def redirect_target!(url, location)
      target = begin
        URI.join(url, location)
      rescue URI::Error => e
        raise UpdateError, "invalid redirect target #{location.inspect} from #{url} (#{e.message})"
      end
      unless ALLOWED_SCHEMES.include?(target.scheme)
        raise UpdateError,
              "refusing redirect from #{url} to non-http(s) target #{location.inspect} " \
              "(scheme #{target.scheme.inspect})"
      end
      if target.host.nil? || target.host.empty?
        raise UpdateError, "refusing redirect from #{url} to hostless target #{location.inspect}"
      end

      target
    end
  end
end
