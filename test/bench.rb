# frozen_string_literal: true

# Lookup latency against the REAL bundled seed (not a fixture): the number
# that backs the "microseconds, offline" claim. Run: rake bench
# Not a Minitest file on purpose — perf assertions in CI are flaky-by-design;
# this is a measurement tool. PRD acceptance: ≤25µs/lookup packed on CI-class
# hardware (the validation prototype measured 19.2µs at the same data scale).
abort("set RUN_BENCH=1 (or use `rake bench`)") unless ENV["RUN_BENCH"] == "1"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "openasn"
require "benchmark"

SAMPLES = 200_000

%i[packed arrays].each do |mode|
  OpenASN.reset!
  OpenASN.configure do |c|
    c.data_dir = File.join(Dir.tmpdir, "openasn-bench-nonexistent") # force seed
    c.memory_mode = mode
  end

  load_time = Benchmark.realtime { OpenASN.eager_load! }

  rng = Random.new(42)
  ips = Array.new(SAMPLES) { rng.rand(0x01000000..0xDF000000) }
  ips.map! { |i| [i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, i & 255].join(".") }

  # warmup
  ips.first(5_000).each { |ip| OpenASN.lookup(ip) }

  elapsed = Benchmark.realtime { ips.each { |ip| OpenASN.lookup(ip) } }
  per = elapsed / SAMPLES * 1_000_000

  rss_mb = `ps -o rss= -p #{Process.pid}`.to_i / 1024.0
  puts format("%-7s load=%.0fms  %.1fµs/lookup  (~%dk lookups/sec/core)  RSS=%.0fMB",
              mode, load_time * 1000, per, (1.0 / per * 1000).round, rss_mb)
end
