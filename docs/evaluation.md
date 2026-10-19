# Evaluation: alerts vs incidents

All numbers below were measured by running `EvaluationRunner` on seeded synthetic data; nothing is typed in by hand. Re-run it to reproduce them (timings depend on the machine).

## 1. Main run (seed 42, default settings)

Settings: brute force = 5 failures within 10 s; fail-then-success = 3 failures then a success within 60 s; correlation window = 300 s, matched by source.

| Measure | Value |
|---|---|
| Events (normal) | 2867 (2226) |
| Injected attacks | 50 |
| Raw alerts (true / false) | 108 (72 / 36) |
| Alert precision | 66.7% |
| Attack recall | 80.0% (40 of 50) |
| F1 | 0.727 |
| False-positive rate (false alerts / normal events) | 1.6% |
| Incidents after correlation | 75 |
| Alert reduction (1 - incidents / alerts) | 30.6% |
| Attacks split over several incidents | 0 |
| Incidents mixing several attacks | 0 |
| Incidents with no real attack | 35 |
| Detection + correlation time | 49.5 ms (57925 events/s) |

## 2. Which rule finds what (seed 42)

| Rules | Alerts | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|---|
| Brute force only | 57 | 100.0% | 68.0% | 0.810 | 0.0% |
| Fail-then-success only | 51 | 29.4% | 30.0% | 0.297 | 1.6% |
| Both | 108 | 66.7% | 80.0% | 0.727 | 1.6% |

## 3. Brute-force threshold sweep (seed 42, fail-then-success on)

| Threshold (failures in 10 s) | Alerts | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|---|
| 3 | 125 | 65.6% | 80.0% | 0.721 | 1.9% |
| 5 | 108 | 66.7% | 80.0% | 0.727 | 1.6% |
| 8 | 91 | 60.4% | 80.0% | 0.689 | 1.6% |
| 10 | 72 | 50.0% | 62.0% | 0.554 | 1.6% |

## 4. Correlation window sweep (seed 42)

| Window | Alerts | Incidents | Reduction | Attacks split | Incidents mixing attacks |
|---|---|---|---|---|---|
| 0 s | 108 | 108 | 0.0% | 23 | 0 |
| 60 s | 108 | 75 | 30.6% | 0 | 0 |
| 300 s | 108 | 75 | 30.6% | 0 | 0 |
| 900 s | 108 | 70 | 35.2% | 0 | 0 |

## 5. Stability over 10 seeds (default settings)

| Measure | Mean | Min | Max |
|---|---|---|---|
| Alert precision | 72.7% | 68.6% | 75.5% |
| Attack recall | 80.0% | 80.0% | 80.0% |
| F1 | 76.2% | 73.9% | 77.7% |
| False-positive rate | 1.4% | 1.2% | 1.7% |
| Alert reduction | 37.4% | 33.0% | 41.0% |

## 6. How to read this

- Precision = true alerts / all alerts. A true alert cites at least one injected-attack event.
- Recall = attacks with at least one true alert / all injected attacks.
- FP rate = false alerts / normal events (the PRD definition, not the textbook one).
- Alert reduction = 1 - incidents / alerts.
- The data is synthetic and the attack types are simple, so the results show that the pipeline works as designed. They are not a claim about real-world accuracy.
- Known weaknesses the data exposes: forgetful users who fail 3 or more times and then succeed look like compromises (false alerts), and low-and-slow attacks are missed by the short-window brute-force rule.
