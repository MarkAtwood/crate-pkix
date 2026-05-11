# pkix-difftest baseline (Tier-3 CT scrape: Cloudflare Nimbus2026, 1000 chains)

## Summary

| Class | Count |
|---|---:|
| LooserThanWild | 40 |
| StricterThanWild | 479 |
| OracleDivergence | 0 |
| DiagnosticDivergence | 0 |
| Agreement | 481 |
| **Total** | 1000 |

## LooserThanWild (40)

### `entry-4189418554/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418620/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418662/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418667/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418753/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418768/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418774/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418809/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418832/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

### `entry-4189418850/chain.pem`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Neither EKU nor anyEKU could be found)

_(30 additional sample(s) in this class omitted; see JSON report.)_

## StricterThanWild (479)

### `entry-4189418507/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418508/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418509/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418513/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418514/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418517/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418518/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418520/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418524/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 1)
  * openssl: Pass
  * pyca: Pass

### `entry-4189418527/chain.pem`

* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Pass

_(469 additional sample(s) in this class omitted; see JSON report.)_

## Agreement (481)

### `entry-4189418511/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418512/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418519/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418521/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418523/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418526/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418529/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418530/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418531/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `entry-4189418535/chain.pem`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

_(471 additional sample(s) in this class omitted; see JSON report.)_

