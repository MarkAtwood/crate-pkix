# PKITS baseline (pkix-path vs openssl vs pyca)

## Summary

| Class | Count |
|---|---:|
| LooserThanWild | 63 |
| StricterThanWild | 56 |
| OracleDivergence | 0 |
| DiagnosticDivergence | 67 |
| Agreement | 61 |
| **Total** | 247 |

## Ground-truth disagreements

1 chain(s) where pkix-path's verdict disagrees with the corpus's expected verdict. This category is orthogonal to oracle-classification — it counts pkix-path-vs-PKITS only, regardless of what the other oracles say.

### `4.1.4 Valid DSA Signatures Test4`

* Ground truth: DISAGREES
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature not verified at chain index 0: unsupported signature algorithm)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Forbidden public key algorithm: AlgorithmIdentifier { oid: DefinedByMarker(PhantomData<asn1::object_identifier::ObjectIdentifier>), params: Dsa(DssParams { p: BigUint { data: [0, 223, 229, 17, 62, 218, 233, 182, 110, 16, 214, 234, 157, 226, 157, 58, 176, 71, 189, 68, 0, 199, 86, 200, 204, 110, 208, 51, 132, 86, 71, 53, 61, 246, 84, 200, 227, 194, 173, 187, 186, 117, 243, 47, 51, 12, 166, 249, 49, 236, 103, 227, 229, 153, 109, 252, 41, 110, 170, 87, 136, 114, 52, 226, 142, 0, 144, 224, 163, 172, 100, 142, 192, 246, 60, 29, 143, 180, 200, 74, 72, 48, 94, 127, 170, 156, 118, 38, 11, 219, 19, 115, 51, 131, 151, 192, 197, 179, 230, 55, 245, 62, 255, 21, 13, 212, 161, 46, 186, 49, 248, 171, 135, 216, 11, 204, 119, 152, 66, 110, 172, 147, 152, 194, 189, 46, 123, 52, 11] }, q: BigUint { data: [0, 207, 6, 4, 216, 255, 139, 235, 0, 233, 246, 92, 7, 150, 115, 253, 150, 101, 58, 47, 7] }, g: BigUint { data: [0, 204, 225, 124, 176, 206, 146, 95, 99, 236, 56, 187, 68, 186, 221, 146, 52, 182, 94, 190, 101, 123, 216, 113, 119, 4, 157, 236, 102, 124, 59, 4, 206, 182, 243, 82, 254, 15, 146, 85, 2, 239, 78, 18, 171, 93, 154, 46, 47, 110, 86, 243, 112, 236, 106, 237, 155, 34, 184, 168, 19, 203, 12, 156, 22, 234, 193, 10, 142, 33, 38, 68, 165, 12, 249, 160, 236, 98, 224, 112, 49, 204, 104, 245, 11, 133, 164, 74, 27, 110, 121, 244, 193, 249, 54, 90, 56, 111, 78, 239, 132, 83, 223, 103, 253, 204, 247, 89, 98, 143, 156, 156, 205, 16, 143, 92, 164, 15, 156, 183, 7, 236, 96, 243, 190, 175, 126, 57, 152] } }) })

## LooserThanWild (63)

### `4.10.1.1 Valid Policy Mapping Test1 (Subpart 1)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.1.2 Valid Policy Mapping Test1 (Subpart 2)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.1.3 Valid Policy Mapping Test1 (Subpart 3)`

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

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.12 Valid Policy Mapping Test12 (Subpart 2)`

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

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.13 Valid Policy Mapping Test13 (Subpart 3)`

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

### `4.10.3 Valid Policy Mapping Test3 (Subpart 1)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.3 Valid Policy Mapping Test3 (Subpart 2)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.5 Valid Policy Mapping Test5 (Subpart 1)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.5 Valid Policy Mapping Test5 (Subpart 2)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.6 Valid Policy Mapping Test6 (Subpart 1)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.6 Valid Policy Mapping Test6 (Subpart 2)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.10.9 Valid Policy Mapping Test9`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.2 Valid inhibitPolicyMapping Test2`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.4 Valid inhibitPolicyMapping Test4`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.7 Valid Self-Issued inhibitPolicyMapping Test7`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.12.2 Valid inhibitAnyPolicy Test2`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.3 inhibitAnyPolicy Test3 (Subpart 1)`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.3 inhibitAnyPolicy Test3 (Subpart 2)`

* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.7 Valid Self-Issued inhibitAnyPolicy Test7`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.9 Valid Self-Issued inhibitAnyPolicy Test9`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: signature does not match)

### `4.13.1 Valid DN nameConstraints Test1`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.11 Valid DN nameConstraints Test11`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.14 Valid DN nameConstraints Test14`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.18 Valid DN nameConstraints Test18`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.19 Valid Self-Issued DN nameConstraints Test19`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.27 Valid DN and RFC822 nameConstraints Test27`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.34 Valid URI nameConstraints Test34`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: unsupported name constraint)

### `4.13.36 Valid URI nameConstraints Test36`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: unsupported name constraint)

### `4.13.4 Valid DN nameConstraints Test4`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.5 Valid DN nameConstraints Test5`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.6 Valid DN nameConstraints Test6`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.14.18 Valid onlySomeReasons Test18`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.19 Valid onlySomeReasons Test19`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.22 Valid IDP with indirectCRL Test22`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.24 Valid IDP with indirectCRL Test24`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.25 Valid IDP with indirectCRL Test25`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.28 Valid cRLIssuer Test28`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.29 Valid cRLIssuer Test29`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.30 Valid cRLIssuer Test30`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.33 Valid cRLIssuer Test33`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.15.5 Valid delta-CRL Test5`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(pyca: certificate 0x4 revoked by CRL)

### `4.15.7 Valid delta-CRL Test7`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(pyca: certificate 0x6 revoked by CRL)

### `4.2.4 Valid GeneralizedTime notBefore Date Test4`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: validity dates between 1950 and 2049 must be UtcTime (encountered processing <Certificate(subject=<Name(CN=Valid GeneralizedTime notBefore Date EE Certificate Test4,O=Test Certificates 2011,C=US)>, ...)>))

### `4.3.10 Valid Rollover from PrintableString to UTF8String Test10`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: all candidates exhausted with no interior errors)

### `4.3.11 Valid UTF8String Case Insensitive Match Test11`

* Ground truth: matches
* Class: `LooserThanWild`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: all candidates exhausted with no interior errors)

_(13 additional sample(s) in this class omitted; see JSON report.)_

## StricterThanWild (56)

### `4.1.4 Valid DSA Signatures Test4`

* Ground truth: DISAGREES
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(signature not verified at chain index 0: unsupported signature algorithm)
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

### `4.11.3 Invalid inhibitPolicyMapping Test3`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.5 Invalid inhibitPolicyMapping Test5`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.6 Invalid inhibitPolicyMapping Test6`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.8 Invalid Self-Issued inhibitPolicyMapping Test8`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.11.9 Invalid Self-Issued inhibitPolicyMapping Test9`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.33: certificate contains unaccounted-for critical extensions)

### `4.12.1 Invalid inhibitAnyPolicy Test1`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.4 Invalid inhibitAnyPolicy Test4`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.5 Invalid inhibitAnyPolicy Test5`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.6 Invalid inhibitAnyPolicy Test6`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.12.8 Invalid Self-Issued inhibitAnyPolicy Test8`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 1)
  * openssl: Pass
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: invalid extension: 2.5.29.54: certificate contains unaccounted-for critical extensions)

### `4.14.11 Invalid onlyContainsUserCerts CRL Test11`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.12 Invalid onlyContainsCACerts CRL Test12`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.14 Invalid onlyContainsAttributeCerts Test14`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.17 Invalid onlySomeReasons Test17`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 4 checker(s) built from the 2 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.26 Invalid IDP with indirectCRL Test26`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.27 Invalid cRLIssuer Test27`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.3 Invalid distributionPoint Test3`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.31 Invalid cRLIssuer Test31`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.32 Invalid cRLIssuer Test32`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 09 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.35 Invalid cRLIssuer Test35`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.14.8 Invalid distributionPoint Test8`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.14.9 Invalid distributionPoint Test9`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(different CRL scope)
  * pyca: Pass

### `4.15.1 Invalid deltaCRLIndicator No Base Test1`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Pass
  * pyca: Pass

### `4.15.10 Invalid delta-CRL Test10`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 2 applicable CRL(s) produced a verdict)
  * openssl: Pass
  * pyca: Pass

### `4.15.3 Invalid delta-CRL Test3`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Pass
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.4.1 Missing CRL Test1`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.4.10 Invalid Unknown CRL Extension Test10`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(unhandled critical CRL extension)
  * pyca: Pass

### `4.4.11 Invalid Old CRL nextUpdate Test11`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(CRL has expired)
  * pyca: Pass

### `4.4.12 Invalid pre2000 CRL nextUpdate Test12`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(CRL has expired)
  * pyca: Pass

### `4.4.21 Invalid Separate Certificate and CRL Keys Test21`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 1 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.4.4 Invalid Bad CRL Signature Test4`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(CRL signature failure)
  * pyca: Pass

### `4.4.5 Invalid Bad CRL Issuer Name Test5`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.4.6 Invalid Wrong CRL Test6`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 0 checker(s) built from the 0 applicable CRL(s) produced a verdict)
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Pass

### `4.7.4 Invalid keyUsage Critical cRLSign False Test4`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 1 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(key usage does not include CRL signing)
  * pyca: Pass

### `4.7.5 Invalid keyUsage Not Critical cRLSign False Test5`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 1 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(key usage does not include CRL signing)
  * pyca: Pass

### `4.8.12 Different Policies Test12`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `4.8.4 Different Policies Test4`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `4.8.5 Different Policies Test5`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Pass

### `4.8.7 Different Policies Test7`

* Ground truth: matches
* Class: `StricterThanWild`
* Verdicts:
  * pkix-path: Fail(certificate policy violation at chain index 0)
  * openssl: Pass
  * pyca: Pass

_(6 additional sample(s) in this class omitted; see JSON report.)_

## DiagnosticDivergence (67)

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
  * pkix-path: Fail(signature not verified at chain index 0: unsupported signature algorithm)
  * openssl: Fail(certificate signature failure)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: Forbidden public key algorithm: AlgorithmIdentifier { oid: DefinedByMarker(PhantomData<asn1::object_identifier::ObjectIdentifier>), params: Dsa(DssParams { p: BigUint { data: [0, 223, 229, 17, 62, 218, 233, 182, 110, 16, 214, 234, 157, 226, 157, 58, 176, 71, 189, 68, 0, 199, 86, 200, 204, 110, 208, 51, 132, 86, 71, 53, 61, 246, 84, 200, 227, 194, 173, 187, 186, 117, 243, 47, 51, 12, 166, 249, 49, 236, 103, 227, 229, 153, 109, 252, 41, 110, 170, 87, 136, 114, 52, 226, 142, 0, 144, 224, 163, 172, 100, 142, 192, 246, 60, 29, 143, 180, 200, 74, 72, 48, 94, 127, 170, 156, 118, 38, 11, 219, 19, 115, 51, 131, 151, 192, 197, 179, 230, 55, 245, 62, 255, 21, 13, 212, 161, 46, 186, 49, 248, 171, 135, 216, 11, 204, 119, 152, 66, 110, 172, 147, 152, 194, 189, 46, 123, 52, 11] }, q: BigUint { data: [0, 207, 6, 4, 216, 255, 139, 235, 0, 233, 246, 92, 7, 150, 115, 253, 150, 101, 58, 47, 7] }, g: BigUint { data: [0, 204, 225, 124, 176, 206, 146, 95, 99, 236, 56, 187, 68, 186, 221, 146, 52, 182, 94, 190, 101, 123, 216, 113, 119, 4, 157, 236, 102, 124, 59, 4, 206, 182, 243, 82, 254, 15, 146, 85, 2, 239, 78, 18, 171, 93, 154, 46, 47, 110, 86, 243, 112, 236, 106, 237, 155, 34, 184, 168, 19, 203, 12, 156, 22, 234, 193, 10, 142, 33, 38, 68, 165, 12, 249, 160, 236, 98, 224, 112, 49, 204, 104, 245, 11, 133, 164, 74, 27, 110, 121, 244, 193, 249, 54, 90, 56, 111, 78, 239, 132, 83, 223, 103, 253, 204, 247, 89, 98, 143, 156, 156, 205, 16, 143, 92, 164, 15, 156, 183, 7, 236, 96, 243, 190, 175, 126, 57, 152] } }) })

### `4.13.10 Invalid DN nameConstraints Test10`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.12 Invalid DN nameConstraints Test12`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.13 Invalid DN nameConstraints Test13`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.15 Invalid DN nameConstraints Test15`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.16 Invalid DN nameConstraints Test16`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.17 Invalid DN nameConstraints Test17`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.2 Invalid DN nameConstraints Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.20 Invalid Self-Issued DN nameConstraints Test20`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

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

### `4.13.29 Invalid DN and RFC822 nameConstraints Test29`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.3 Invalid DN nameConstraints Test3`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

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

### `4.13.35 Invalid URI nameConstraints Test35`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: unsupported name constraint)

### `4.13.37 Invalid URI nameConstraints Test37`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: unsupported name constraint)

### `4.13.38 Invalid DNS nameConstraints Test38`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(permitted subtree violation)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: no permitted name constraints matched SAN)

### `4.13.7 Invalid DN nameConstraints Test7`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.8 Invalid DN nameConstraints Test8`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.13.9 Invalid DN nameConstraints Test9`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(name constraints violated at certificate index 0)
  * openssl: Fail(excluded subtree violation)
  * pyca: Fail(VerificationError: validation failed: fatal error: critical nameConstraints extension contains an unsupported directoryName constraint)

### `4.14.15 Invalid onlySomeReasons Test15`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 01 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x1 revoked by CRL)

### `4.14.16 Invalid onlySomeReasons Test16`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason certificateHold))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.14.2 Invalid distributionPoint Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.14.20 Invalid onlySomeReasons Test20`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.14.21 Invalid onlySomeReasons Test21`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 03 is revoked (reason affiliationChanged))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x3 revoked by CRL)

### `4.14.23 Invalid IDP with indirectCRL Test23`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.14.34 Invalid cRLIssuer Test34`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 0B is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0xb revoked by CRL)

### `4.14.6 Invalid distributionPoint Test6`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.15.4 Invalid delta-CRL Test4`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 03 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x3 revoked by CRL)

### `4.15.6 Invalid delta-CRL Test6`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 05 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x5 revoked by CRL)

### `4.15.9 Invalid delta-CRL Test9`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.16.2 Invalid Unknown Critical Certificate Extension Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(unhandled critical extension at chain index 0)
  * openssl: Fail(unhandled critical extension)
  * pyca: Fail(VerificationError: validation failed: invalid extension: 2.16.840.1.101.2.1.12.2: certificate contains unaccounted-for critical extensions (encountered processing <Certificate(subject=<Name(CN=Invalid Unknown Critical Certificate Extension EE Cert Test2,O=Test Certificates 2011,C=US)>, ...)>))

### `4.2.1 Invalid CA notBefore Date Test1`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(validity period check failed at chain index 1)
  * openssl: Fail(certificate is not yet valid)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: cert is not valid at validation time)

### `4.2.2 Invalid EE notBefore Date Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(validity period check failed at chain index 0)
  * openssl: Fail(certificate is not yet valid)
  * pyca: Fail(VerificationError: validation failed: cert is not valid at validation time (encountered processing <Certificate(subject=<Name(CN=Invalid EE notBefore Date EE Certificate Test2,O=Test Certificates 2011,C=US)>, ...)>))

### `4.2.5 Invalid CA notAfter Date Test5`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(validity period check failed at chain index 1)
  * openssl: Fail(certificate has expired)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: cert is not valid at validation time)

### `4.2.6 Invalid EE notAfter Date Test6`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(validity period check failed at chain index 0)
  * openssl: Fail(certificate has expired)
  * pyca: Fail(VerificationError: validation failed: cert is not valid at validation time (encountered processing <Certificate(subject=<Name(CN=Invalid EE notAfter Date EE Certificate Test6,O=Test Certificates 2011,C=US)>, ...)>))

### `4.2.7 Invalid pre2000 UTC EE notAfter Date Test7`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(validity period check failed at chain index 0)
  * openssl: Fail(certificate has expired)
  * pyca: Fail(VerificationError: validation failed: validity dates between 1950 and 2049 must be UtcTime (encountered processing <Certificate(subject=<Name(CN=Invalid pre2000 UTC EE notAfter Date EE Certificate Test7,O=Test Certificates 2011,C=US)>, ...)>))

### `4.3.1 Invalid Name Chaining EE Test1`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(issuer/subject linkage broken at chain index 0)
  * openssl: Fail(unable to get local issuer certificate)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: all candidates exhausted with no interior errors)

### `4.3.2 Invalid Name Chaining Order Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(issuer/subject linkage broken at chain index 0)
  * openssl: Fail(unable to get local issuer certificate)
  * pyca: Fail(VerificationError: validation failed: candidates exhausted: all candidates exhausted with no interior errors)

### `4.4.15 Invalid Negative Serial Number Test15`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate FF is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(VerificationError: validation failed: certificate serial number cannot be negative (encountered processing <Certificate(subject=<Name(CN=Invalid Negative Serial Number EE Certificate Test15,O=Test Certificates 2011,C=US)>, ...)>))

### `4.4.18 Invalid Long Serial Number Test18`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 7F:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13 is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0x7f0102030405060708090a0b0c0d0e0f10111213 revoked by CRL)

### `4.4.2 Invalid Revoked CA Test2`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 1 revoked by CRL: certificate 0E is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0xe revoked by CRL)

### `4.4.20 Invalid Separate Certificate and CRL Keys Test20`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 02 is revoked (reason keyCompromise))
  * openssl: Fail(unable to get certificate CRL)
  * pyca: Fail(pyca: certificate 0x2 revoked by CRL)

### `4.4.3 Invalid Revoked EE Test3`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: cert at chain index 0 revoked by CRL: certificate 0F is revoked (reason keyCompromise))
  * openssl: Fail(certificate revoked)
  * pyca: Fail(pyca: certificate 0xf revoked by CRL)

### `4.4.8 Invalid Unknown CRL Entry Extension Test8`

* Ground truth: matches
* Class: `DiagnosticDivergence`
* Verdicts:
  * pkix-path: Fail(pkix-path revocation: revocation status of cert at chain index 0 is undetermined — none of the 2 checker(s) built from the 1 applicable CRL(s) produced a verdict)
  * openssl: Fail(unhandled critical CRL extension)
  * pyca: Fail(pyca: certificate 0x1 revoked by CRL)

_(17 additional sample(s) in this class omitted; see JSON report.)_

## Agreement (61)

### `4.1.1 Valid Signatures Test1`

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

### `4.13.30 Valid DNS nameConstraints Test30`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.13.32 Valid DNS nameConstraints Test32`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.1 Valid distributionPoint Test1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.10 Valid No issuingDistributionPoint Test10`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.13 Valid onlyContainsCACerts CRL Test13`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.4 Valid distributionPoint Test4`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.5 Valid distributionPoint Test5`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.14.7 Valid distributionPoint Test7`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.15.2 Valid delta-CRL Test2`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.15.8 Valid delta-CRL Test8`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.16.1 Valid Unknown Not Critical Certificate Extension Test1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.2.8 Valid GeneralizedTime notAfter Date Test8`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.3.6 Valid Name Chaining UIDs Test6`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.3.7 Valid RFC3280 Mandatory Attribute Types Test7`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.3.8 Valid RFC3280 Optional Attribute Types Test8`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.3.9 Valid UTF8String Encoded Names Test9`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.4.13 Valid GeneralizedTime CRL nextUpdate Test13`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.4.14 Valid Negative Serial Number Test14`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.4.16 Valid Long Serial Number Test16`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.4.17 Valid Long Serial Number Test17`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.4.7 Valid Two CRLs Test7`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.5.1 Valid Basic Self-Issued Old With New Test1`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.5.3 Valid Basic Self-Issued New With Old Test3`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.6.13 Valid pathLenConstraint Test13`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.6.14 Valid pathLenConstraint Test14`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.6.7 Valid pathLenConstraint Test7`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.6.8 Valid pathLenConstraint Test8`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.7.3 Valid keyUsage Not Critical Test3`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.1 All Certificates Same Policy Test1 (Subpart 1)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.1 All Certificates Same Policy Test1 (Subpart 2)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.1 All Certificates Same Policy Test1 (Subpart 3)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.1 All Certificates Same Policy Test1 (Subpart 4)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.10 All Certificates Same Policies Test10 (Subpart 1)`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.10 All Certificates Same Policies Test10 (Subpart 2)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.10 All Certificates Same Policies Test10 (Subpart 3)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.11 All Certificates AnyPolicy Test11 (Subpart 1)`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.11 All Certificates AnyPolicy Test11 (Subpart 2)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.13 All Certificates Same Policies Test13 (Subpart 1)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.13 All Certificates Same Policies Test13 (Subpart 2)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.13 All Certificates Same Policies Test13 (Subpart 3)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.14 AnyPolicy Test14 (Subpart 1)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.14 AnyPolicy Test14 (Subpart 2)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.15 User Notice Qualifier Test15`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.16 User Notice Qualifier Test16`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.17 User Notice Qualifier Test17`

* Ground truth: matches
* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

### `4.8.18 User Notice Qualifier Test18 (Subpart 1)`

* Class: `Agreement`
* Verdicts:
  * pkix-path: Pass
  * openssl: Pass
  * pyca: Pass

_(11 additional sample(s) in this class omitted; see JSON report.)_

