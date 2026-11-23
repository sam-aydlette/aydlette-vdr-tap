# Changelog

## 0.1.0

The first release. It implements the method of
[Vulnerability Evidence as a Product](https://samaydlette.com/research/vulnerability-evidence.html) as a TAP plugin.

- Reconciliation of declared exposure with observations (Figure 6), with gates G1 to G5 and G7.
- Likely exploitability (Figure 7), with the optional SSVC overlay.
- The impact rating from the decision tables, under a governed profile.
- The environmental vector: evidence-backed Attack Vector and Privileges Required, applied before the vector is read.
- Dispositions with review dates, the clock, and the decision queue.
- Four Searches: `aydlette-pain`, `aydlette-reconcile`, `aydlette-summary` and `aydlette-coverage`.
- A collector that writes the results as `fedramp_20x_vdr` evaluations.

Not everything in the paper is built. The specification's Paper Coverage table gives the count, and the README lists
what is not in this release. Requires TAP 0.4.3 or later.
