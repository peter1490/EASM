# Asset risk scoring

How an asset's findings become one number, why the number runs 0–1000, and what the
commercial tools do that this borrows from.

## The problem with the previous model

```
risk_score = min(100, (exposure_score + Σ finding_score) × importance_multiplier)
```

Every term is defensible on its own. The combination could not rank an attack surface,
because the sum has no ceiling and the display range does.

Measured over a synthetic population of 4,000 assets:

| | old model | new model |
|---|---|---|
| assets pinned at the maximum | **41%** | 0% |
| distinct scores among the worst 400 assets | **1** | 95 |
| assets rated critical | 47% | 19% |

Two findings of CVSS 9.8 were enough to reach 100.0. Past that point the score carried
no information, so the triage queue was ordered arbitrarily exactly where ordering
mattered most. No choice of constants fixes this — a linear sum against a hard cap
saturates by construction.

Four further faults, each worth naming because the replacement addresses each one:

1. **CVSS was counted twice.** `severity_score + cvss × 2`, where the severity band is
   itself derived from the CVSS. A CVSS 9.8 scored 40 (critical) + 19.6 = 59.6 out of
   100 on its own.
2. **Threat intelligence was collected and discarded.** `security_scan_service` already
   writes CISA KEV membership, ransomware-campaign linkage and the FIRST EPSS
   probability into every `known_cve` finding's `data` column. Scoring read none of it,
   so a CVE under active ransomware use and a dormant one with the same CVSS were the
   same number.
3. **Importance could only inflate.** `1 + 0.2 × importance` meant an asset explicitly
   marked *Negligible* (1) scored 20% **higher** than an unrated one (0), and marking
   something unimportant could never deprioritise it.
4. **Repeats damped by finding type, not by cause.** Thirty distinct CVEs on an
   unpatched host damped against each other as though they were one repeated
   misconfiguration.

## What the industry does

| Tool | Range | Aggregation | Threat signal |
|---|---|---|---|
| [Qualys TruRisk](https://docs.qualys.com/en/vmdr/latest/mergedProjects/search_in_vmdr/threat/calculating_asset_risk_score.htm) | 0–1000 | `ACS × Σ_severity w·avg(QDS)·count^0.01` — average per band with a near-flat volume term | QDS folds in exploit maturity |
| [Tenable AES](https://docs.tenable.com/vulnerability-management/Content/Lumin/LuminMetrics.htm) | 0–1000 | vulnerability density × ACR (1–10), scaled | VPR, seven drivers incl. threat |
| [Rapid7 Active Risk](https://docs.rapid7.com/insightvm/working-with-risk-strategies-to-analyze-threats/) | 0–1000 | CVSS + threat feeds | AttackerKB, Metasploit, CISA KEV |
| [Bitsight](https://help.bitsighttech.com/hc/en-us/articles/231950968-How-are-Bitsight-Security-Ratings-Calculated) | 250–900 | percentile rank per risk vector, weighted sum | population-relative |
| [CISA SSVC](https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc) | 4 decisions | decision tree, not a score | Exploitation is the first branch |
| [FIRST EPSS](https://www.first.org/epss/) | 0–1 | probability of exploitation in 30 days | *is* the threat signal |

Three lessons, all of which the new model applies:

- **0–1000, not 0–100.** Everyone converged here. The interesting assets live in the
  last few percent of the range, and a hundred integers cannot separate them.
- **Likelihood is a separate axis from impact.** EPSS v3 reaches 90% coverage at 24%
  efficiency where CVSS-based prioritisation manages roughly 35% coverage at 6%. The
  gap is entirely about *who is actually being attacked*.
- **Volume must be sublinear.** Qualys uses `count^0.01`; Tenable damps low and medium
  weights. Nobody sums linearly, because a long tail of dormant findings otherwise
  outranks a short list of exploited ones.

## The model

Implemented in [`backend/src/services/risk_model.rs`](../backend/src/services/risk_model.rs).

### 1. Per finding — impact × likelihood, 0–100

```
impact     = cvss × 10, or the severity band midpoint when there is no CVSS (never both)
likelihood = 1.00  CISA KEV (exploited in the wild)
             …     EPSS, log-scaled: 0.25 + 0.75 · (log₁₀(p) + 4)/4
             0.65  public exploit code exists
             0.55  condition observed directly by a scanner (not a CVE)
             0.50  CVE with no EPSS score
             0.25  EPSS scored it near zero
age        = 1 + 0.25 · min(1, days_open / 180)

finding_score = clamp(0..100, impact × likelihood × age × type_multiplier)
```

The EPSS curve is logarithmic because the EPSS distribution is extremely right-skewed —
a probability of 0.1 already sits near the 88th percentile, so a linear reading flattens
almost every CVE to zero. This is the same mapping `ThreatContext::threat_score` already
applies when ranking CVEs at scan time.

A CVE with **no** EPSS score scores *above* one EPSS scored near zero. A feed with no row
is uncertainty; a feed returning a low probability is evidence. Conflating them would bury
every CVE too new for EPSS to have reached — and "too new" is when a CVE is most dangerous.

A finding CISA links to a live ransomware campaign floors at 95.

### 2. Aggregation — hazard, not sum

Each finding's score becomes a *hazard*, `h = −ln(1 − p)` where `p = 0.97 · (score/100)^1.5`.
Hazards add, and summing them is exactly the probabilistic union `1 − Π(1 − pᵢ)` — "the
chance at least one of these is the way in". This is the aggregation the
[NIST attack-graph work](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=926022)
argues for, and it needs no clamp: it is bounded once projected, yet strictly increasing
in every finding, so no two assets tie unless their findings are identical.

Damping happens in two stages:

- **Within a root cause** (`0.75^rank`): the CVE when there is one, the finding type
  otherwise. One CVE found on five ports stays one problem; five different CVEs stay
  five. Bounds any single cause at 4× its own worst finding.
- **Across root causes** (`0.92^rank`): distinct problems genuinely add up, but shallowly
  enough that thirty dormant CVEs never outrank three under active attack.

A soft floor — `(H^4 + f^4)^(1/4)` — keeps an asset's band from contradicting the severity
shown beside it: 0.85 for any critical finding, 0.45 for any high, **2.8 for anything in
CISA KEV** (SSVC puts known-exploited straight into "Act"). Soft rather than `max`, so the
assets it lifts stay ordered among themselves.

### 3. Exposure and importance scale the hazard

```
exposure    ip 1.0 · domain 0.95 · port 0.9 · certificate 0.6 · asn/org 0.4
importance  negligible 0.5 · low 0.75 · normal 1.0 · high 1.4 · business critical 2.0
```

Both multiply the hazard rather than the score, so they move an asset *along* the curve
instead of pushing it into a ceiling. Importance now moves in both directions, and an
unrated asset is treated as Normal rather than as worse than Negligible.

### 4. Projection to 0–1000

```
risk_score = 1000 · H^1.3 / (H^1.3 + 1.05^1.3)
```

A logistic in log-space. It never reaches 1000, is strictly increasing everywhere, and
approaches the ceiling as a power law rather than exponentially — so it keeps resolving
assets long after `1 − e^−H` has flattened. Doubling the hazard of an already-bad asset
still moves its score by tens of points.

Bands: **critical ≥ 800, high ≥ 600, medium ≥ 400, low ≥ 200**, informational below.

## Calibration

Reference assets, scored end to end:

| asset | score | band |
|---|---:|---|
| clean domain | 0 | info |
| domain missing all seven security headers | 172 | info |
| the above plus no WAF, no CAA, open ports, technology disclosure | 211 | low |
| the above on an IP, plus a self-signed certificate | 283 | low |
| critical CVE (9.8), no exploitation evidence | 419 | medium |
| same CVE, public exploit code | 443 | medium |
| exposed database | 655 | high |
| same CVE, EPSS 0.42 | 665 | high |
| subdomain takeover | 794 | high |
| same CVE, in CISA KEV | 809 | critical |
| 30 unpatched high CVEs, all dormant | 822 | critical |
| KEV CVE, ransomware-linked, open 200 days | 834 | critical |
| 3 KEV CVEs + exposed database | 921 | critical |
| Log4Shell + exposed database, business-critical asset | 951 | critical |
| everything above at once | 979 | critical |

The constants were chosen by grid search against these target bands rather than by hand;
the search rejected 287 of 288 candidate parameter sets.

## Scale migration

`031_risk_score_scale.sql` stamps existing `asset_risk_history` rows with `scale_max = 100`
and everything written afterwards with 1000, so a trend chart spanning the change does not
read a rescaling as a collapse. Both history read paths normalise onto the current range.

Live `risk_score` values are cleared rather than multiplied by 10: every band boundary
moved and the model changed shape, so rescaling would invent numbers the new model would
never produce. Assets read as "pending calculation" until the next run.

## Explainability

Every calculation stores its full derivation in `asset_risk_history.factors`: the hazard
before and after damping, the exposure and criticality factors, which floor applied, the
root-cause count, and the five highest-scoring findings with their KEV/EPSS/age evidence.
"Why is this asset 951" is answerable without re-running the scan.
