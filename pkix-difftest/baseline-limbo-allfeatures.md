# pkix-difftest report

## Summary

| Class | Count |
|---|---:|
| LooserThanWild | 827 |
| StricterThanWild | 22 |
| OracleDivergence | 0 |
| DiagnosticDivergence | 5898 |
| Agreement | 2979 |
| **Total** | 9726 |

## Ground-truth disagreements

2901 chain(s) where pkix-path's verdict disagrees with the corpus's expected verdict. This category is orthogonal to oracle-classification — it counts pkix-path-vs-PKITS only, regardless of what the other oracles say.

### `bettertls::nameconstraints::tc1471`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1472`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1473`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1480`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1481`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1482`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1489`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1490`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1491`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1492`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(permitted subtree violation)
  * pyca: Pass

_(2891 additional ground-truth disagreement(s) omitted; see JSON report.)_

## LooserThanWild (827)

### `bettertls::nameconstraints::tc1471`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1472`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1473`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1480`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1481`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1482`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1489`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1490`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1491`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(excluded subtree violation)
  * pyca: Pass

### `bettertls::nameconstraints::tc1492`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(permitted subtree violation)
  * pyca: Pass

_(817 additional sample(s) in this class omitted; see JSON report.)_

## StricterThanWild (22)

### `bettertls::nameconstraints::tc8877`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc8878`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9091`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9092`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9219`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9220`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9347`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9348`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9475`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc9476`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(malformed certificate at chain index 0)
  * openssl: Pass
  * pyca: Pass

_(12 additional sample(s) in this class omitted; see JSON report.)_

## DiagnosticDivergence (5898)

### `bettertls::nameconstraints::tc1000`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1001`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1002`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1009`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc101`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1010`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1011`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1018`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1019`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `bettertls::nameconstraints::tc1020`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

_(5888 additional sample(s) in this class omitted; see JSON report.)_

## Agreement (2979)

### `bettertls::nameconstraints::tc0`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc10`

* Ground truth: DISAGREES
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc100`

* Ground truth: DISAGREES
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1003`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1004`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1005`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1006`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1007`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `bettertls::nameconstraints::tc1008`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

_(2969 additional sample(s) in this class omitted; see JSON report.)_

