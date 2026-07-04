# frozen_string_literal: true

# Lookup latency against the REAL bundled seed (not a fixture): the number
# that backs the "microseconds, offline" claim. Run: rake bench
#
# Measured reality (2026-07-04, full classify incl. IP parse + overlays):
#   Apple M-series          packed ~15µs   arrays ~9µs
#   GitHub shared runners   packed ~24-25µs arrays ~11-13µs
# The acceptance target was ≤25µs packed — met, with no margin on shared
# runners' oldest-Ruby lane, comfortably everywhere real apps run.
#
# Not a Minitest file on purpose — tight perf assertions on shared CI are
# flaky-by-design. Instead, BENCH_MAX_US sets a GENEROUS ceiling (CI uses
# 100µs ≈ 4x target) purely as a regression tripwire: it can only fire on
# an algorithmic regression (e.g. binary search accidentally degrading to
# a scan), never on runner noise.
abort("set RUN_BENCH=1 (or use `rake bench`)") unless ENV["RUN_BENCH"] == "1"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "openasn"
require "benchmark"

SAMPLES = 200_000
results = {}

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
  results[mode] = per
end

if ENV["BENCH_MAX_US"]
  ceiling = ENV["BENCH_MAX_US"].to_f
  if results[:packed] > ceiling
    abort format("BENCH REGRESSION: packed lookup %.1fµs exceeds the %.0fµs ceiling — " \
                 "this margin only trips on algorithmic regressions, investigate before merging", results[:packed], ceiling)
  end
  puts format("bench tripwire OK (packed %.1fµs ≤ %.0fµs ceiling)", results[:packed], ceiling)
end
