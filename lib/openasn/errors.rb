# frozen_string_literal: true

module OpenASN
  class Error < StandardError; end

  # Raised for unparseable IP input. Inherits ArgumentError so bare
  # `rescue ArgumentError` in caller code behaves as documented
  # ("raises on invalid IP").
  class InvalidIPError < ArgumentError; end

  # Artifact bytes don't match the OASN/OORG format (truncated download,
  # foreign file, or a format_version this gem doesn't speak).
  class FormatError < Error; end

  # Canonical refresh failed in a way worth surfacing to the caller of
  # OpenASN.update! (Tier B sources never raise — they keep stale data).
  class UpdateError < Error; end

  # A downloaded artifact's SHA-256 didn't match the manifest. The file is
  # discarded and the previous data stays live.
  class IntegrityError < UpdateError; end
end
