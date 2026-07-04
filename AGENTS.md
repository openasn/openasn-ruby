# AGENTS.md

This file provides guidance to AI agents (and humans) working in this repository.

This is the Ruby client for the OpenASN data project. Read `README.md`
first; the data semantics, artifact format (FORMAT.md), precedence
rationale (DECISIONS.md) and legal design live in the data repo:
https://github.com/openasn/openasn

Hard rules:

1. **Zero runtime dependencies.** stdlib only. Rails/ActiveJob integrations
   stay conditionally defined. Do not add gems.
2. **The precedence ladder in lib/openasn/classifier.rb is the product.**
   Each line encodes a documented false-positive lesson; change only with
   the data repo's DECISIONS.md in hand, and mirror spot-panel changes.
3. **Data never ships via gem releases** — the gem versions on code; data
   flows through the nightly GitHub Releases + UpdateJob. (The bundled
   seed is refreshed via `rake seed:refresh` only as part of a code release.)
4. **Readers never block.** Snapshot swaps are single ivar assignments;
   keep locks away from the lookup path.
5. Tests are offline (WebMock). `bundle exec rake test` must stay green on
   Ruby 3.1+.
