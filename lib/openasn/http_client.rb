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
  # * Supports conditional GET via ETag (returns :not_modified).
  # * Never talks to api.github.com (60 req/hr unauthenticated limit);
  #   releases/download/<tag>/ asset URLs redirect fine without auth.
  class HttpClient
    MAX_REDIRECTS = 5
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 120 # artifacts are ~6MB; Apple's relay CSV ~10MB

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

      uri = URI(url)
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

        location = URI.join(url, location).to_s unless location.start_with?("http")
        # Conditional headers stay on the ORIGINAL url's cache identity;
        # redirect targets are one-off signed URLs. Keep method headers such
        # as Content-Type for POST-form provider endpoints.
        redirect_headers = headers.reject { |key, _| key.casecmp("If-None-Match").zero? }
        return request(method, location, redirect_headers, redirects_left - 1, body)
      end
      response
    end
  end
end
