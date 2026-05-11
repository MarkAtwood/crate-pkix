# PKITS baseline (post-PKIX-emf1.4 pyca CRL)

## Summary

| Class | Count |
|---|---:|
| LooserThanWild | 81 |
| StricterThanWild | 46 |
| OracleDivergence | 0 |
| DiagnosticDivergence | 49 |
| Agreement | 71 |
| **Total** | 247 |

## Ground-truth disagreements

46 chain(s) where pkix-path's verdict disagrees with the corpus's expected verdict. This category is orthogonal to oracle-classification — it counts pkix-path-vs-PKITS only, regardless of what the other oracles say.

### `4.10.1.2 Valid Policy Mapping Test1 (Subpart 2)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.1.3 Valid Policy Mapping Test1 (Subpart 3)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.13 Valid Policy Mapping Test13 (Subpart 3)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.3 Valid Policy Mapping Test3 (Subpart 1)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.5 Valid Policy Mapping Test5 (Subpart 2)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.6 Valid Policy Mapping Test6 (Subpart 2)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.12.3 inhibitAnyPolicy Test3 (Subpart 2)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.14.11 Invalid onlyContainsUserCerts CRL Test11`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.12 Invalid onlyContainsCACerts CRL Test12`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.14 Invalid onlyContainsAttributeCerts Test14`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(different CRL scope)
  * pyca: Pass

_(36 additional ground-truth disagreement(s) omitted; see JSON report.)_

## LooserThanWild (81)

### `4.10.1.1 Valid Policy Mapping Test1 (Subpart 1)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.1.2 Valid Policy Mapping Test1 (Subpart 2)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.1.3 Valid Policy Mapping Test1 (Subpart 3)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.11 Valid Policy Mapping Test11`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.12 Valid Policy Mapping Test12 (Subpart 1)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.12 Valid Policy Mapping Test12 (Subpart 2)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.13 Valid Policy Mapping Test13 (Subpart 1)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.13 Valid Policy Mapping Test13 (Subpart 2)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.13 Valid Policy Mapping Test13 (Subpart 3)`

* Ground truth: DISAGREES
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.14 Valid Policy Mapping Test14`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

_(71 additional sample(s) in this class omitted; see JSON report.)_

## StricterThanWild (46)

### `4.1.4 Valid DSA Signatures Test4`

* Ground truth: DISAGREES
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Forbidden public key algorithm: AlgorithmIdentifier { oid: DefinedByMarker(PhantomData<asn1::object_identifier::ObjectIdentifier>), params: Dsa(DssParams { p: BigUint { data: [0, 223, 229, 17, 62, 218, 233, 182, 110, 16, 214, 234, 157, 226, 157, 58, 176, 71, 189, 68, 0, 199, 86, 200, 204, 110, 208, 51, 132, 86, 71, 53, 61, 246, 84, 200, 227, 194, 173, 187, 186, 117, 243, 47, 51, 12, 166, 249, 49, 236, 103, 227, 229, 153, 109, 252, 41, 110, 170, 87, 136, 114, 52, 226, 142, 0, 144, 224, 163, 172, 100, 142, 192, 246, 60, 29, 143, 180, 200, 74, 72, 48, 94, 127, 170, 156, 118, 38, 11, 219, 19, 115, 51, 131, 151, 192, 197, 179, 230, 55, 245, 62, 255, 21, 13, 212, 161, 46, 186, 49, 248, 171, 135, 216, 11, 204, 119, 152, 66, 110, 172, 147, 152, 194, 189, 46, 123, 52, 11] }, q: BigUint { data: [0, 207, 6, 4, 216, 255, 139, 235, 0, 233, 246, 92, 7, 150, 115, 253, 150, 101, 58, 47, 7] }, g: BigUint { data: [0, 204, 225, 124, 176, 206, 146, 95, 99, 236, 56, 187, 68, 186, 221, 146, 52, 182, 94, 190, 101, 123, 216, 113, 119, 4, 157, 236, 102, 124, 59, 4, 206, 182, 243, 82, 254, 15, 146, 85, 2, 239, 78, 18, 171, 93, 154, 46, 47, 110, 86, 243, 112, 236, 106, 237, 155, 34, 184, 168, 19, 203, 12, 156, 22, 234, 193, 10, 142, 33, 38, 68, 165, 12, 249, 160, 236, 98, 224, 112, 49, 204, 104, 245, 11, 133, 164, 74, 27, 110, 121, 244, 193, 249, 54, 90, 56, 111, 78, 239, 132, 83, 223, 103, 253, 204, 247, 89, 98, 143, 156, 156, 205, 16, 143, 92, 164, 15, 156, 183, 7, 236, 96, 243, 190, 175, 126, 57, 152] } }) })

### `4.10.10 Invalid Policy Mapping Test10`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.2 Invalid Policy Mapping Test2 (Subpart 1)`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.2 Invalid Policy Mapping Test2 (Subpart 2)`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.4 Invalid Policy Mapping Test4`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.7 Invalid Mapping From anyPolicy Test7`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 1)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.8 Invalid Mapping To anyPolicy Test8`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 1)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.1 Invalid inhibitPolicyMapping Test1`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.10 Invalid Self-Issued inhibitPolicyMapping Test10`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.11 Invalid Self-Issued inhibitPolicyMapping Test11`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

_(36 additional sample(s) in this class omitted; see JSON report.)_

## DiagnosticDivergence (49)

### `4.1.2 Invalid CA Signature Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 1)
  * openssl: Fail(certificate signature failure)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: signature does not match)

### `4.1.3 Invalid EE Signature Test3`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Fail(certificate signature failure)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: signature does not match)

### `4.1.6 Invalid DSA Signature Test6`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(signature invalid at chain index 0)
  * openssl: Fail(certificate signature failure)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Forbidden public key algorithm: AlgorithmIdentifier { oid: DefinedByMarker(PhantomData<asn1::object_identifier::ObjectIdentifier>), params: Dsa(DssParams { p: BigUint { data: [0, 223, 229, 17, 62, 218, 233, 182, 110, 16, 214, 234, 157, 226, 157, 58, 176, 71, 189, 68, 0, 199, 86, 200, 204, 110, 208, 51, 132, 86, 71, 53, 61, 246, 84, 200, 227, 194, 173, 187, 186, 117, 243, 47, 51, 12, 166, 249, 49, 236, 103, 227, 229, 153, 109, 252, 41, 110, 170, 87, 136, 114, 52, 226, 142, 0, 144, 224, 163, 172, 100, 142, 192, 246, 60, 29, 143, 180, 200, 74, 72, 48, 94, 127, 170, 156, 118, 38, 11, 219, 19, 115, 51, 131, 151, 192, 197, 179, 230, 55, 245, 62, 255, 21, 13, 212, 161, 46, 186, 49, 248, 171, 135, 216, 11, 204, 119, 152, 66, 110, 172, 147, 152, 194, 189, 46, 123, 52, 11] }, q: BigUint { data: [0, 207, 6, 4, 216, 255, 139, 235, 0, 233, 246, 92, 7, 150, 115, 253, 150, 101, 58, 47, 7] }, g: BigUint { data: [0, 204, 225, 124, 176, 206, 146, 95, 99, 236, 56, 187, 68, 186, 221, 146, 52, 182, 94, 190, 101, 123, 216, 113, 119, 4, 157, 236, 102, 124, 59, 4, 206, 182, 243, 82, 254, 15, 146, 85, 2, 239, 78, 18, 171, 93, 154, 46, 47, 110, 86, 243, 112, 236, 106, 237, 155, 34, 184, 168, 19, 203, 12, 156, 22, 234, 193, 10, 142, 33, 38, 68, 165, 12, 249, 160, 236, 98, 224, 112, 49, 204, 104, 245, 11, 133, 164, 74, 27, 110, 121, 244, 193, 249, 54, 90, 56, 111, 78, 239, 132, 83, 223, 103, 253, 204, 247, 89, 98, 143, 156, 156, 205, 16, 143, 92, 164, 15, 156, 183, 7, 236, 96, 243, 190, 175, 126, 57, 152] } }) })

### `4.13.22 Invalid RFC822 nameConstraints Test22`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: no permitted name constraints matched SAN)

### `4.13.24 Invalid RFC822 nameConstraints Test24`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: no permitted name constraints matched SAN)

### `4.13.26 Invalid RFC822 nameConstraints Test26`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

### `4.13.28 Invalid DN and RFC822 nameConstraints Test28`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: no permitted name constraints matched SAN)

### `4.13.3 Invalid DN nameConstraints Test3`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: unsupported name constraint)

### `4.13.31 Invalid DNS nameConstraints Test31`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: no permitted name constraints matched SAN)

### `4.13.33 Invalid DNS nameConstraints Test33`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: excluded name constraint matched SAN)

_(39 additional sample(s) in this class omitted; see JSON report.)_

## Agreement (71)

### `4.1.1 Valid Signatures Test1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.1 Valid DN nameConstraints Test1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.11 Valid DN nameConstraints Test11`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.14 Valid DN nameConstraints Test14`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.18 Valid DN nameConstraints Test18`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.19 Valid Self-Issued DN nameConstraints Test19`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.21 Valid RFC822 nameConstraints Test21`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.23 Valid RFC822 nameConstraints Test23`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.25 Valid RFC822 nameConstraints Test25`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.27 Valid DN and RFC822 nameConstraints Test27`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

_(61 additional sample(s) in this class omitted; see JSON report.)_

