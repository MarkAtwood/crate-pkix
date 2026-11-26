# pkix-truststore-system

**OS trust store adapter for [`pkix-truststore`](https://docs.rs/pkix-truststore).**

Finds where the operating system keeps its trust anchors, reads them, and feeds
them through `pkix-truststore` to produce `Vec<TrustAnchor>`. The
`rustls-native-certs` analogue for the `pkix-truststore` ecosystem.

```rust,no_run
let anchors = pkix_truststore_system::from_system()?;
// hand `&anchors` to pkix_path::validate_path / pkix_chain::verify_chain
# Ok::<(), pkix_truststore_system::Error>(())
```

## Portable first, per-OS second

`SSL_CERT_FILE` and `SSL_CERT_DIR` are consulted first. They are the OpenSSL
convention and the only thing that works reliably in containers, in Nix and
Guix builds, and in any sandbox that relocates the store — a caller who sets
one has made a decision, and it is honoured over anything found on disk.

The default backend then reads PEM bundles and certificate directories. That
is not a Linux feature: it is how trust is exposed on Linux, Android, the
BSDs, illumos, inside every container image, and on macOS whenever a bundle
has been installed by Homebrew, MacPorts or Nix. It needs no FFI and no
platform crate, so it compiles and is testable everywhere.

Keychain and CryptoAPI are layered on top, for the platforms whose canonical
store is not a file. They are selected by target rather than by feature, so a
Linux build never compiles them and a macOS build gets the Keychain reader
without the consumer opting in.

## Why this is not just `from_pem_file`

"The well-known path" is not one path: `/etc/ssl/certs/ca-certificates.crt` on
Debian, Ubuntu, Alpine and Gentoo; `/etc/pki/tls/certs/ca-bundle.crt` on RHEL
and Fedora; `/etc/ssl/ca-bundle.pem` on SUSE; `/etc/ssl/cert.pem` on Alpine
and OpenBSD; `/usr/local/share/certs/ca-root-nss.crt` on FreeBSD; a directory
on Android. A consumer who hard-codes one of them has written a program that
works on their distribution and fails on the next. `candidate_bundle_files`
and `candidate_cert_dirs` are the list, and they are public so it can be
inspected rather than guessed at.

A system bundle is also not all-or-nothing. `pkix_truststore::from_pem_file`
fails the whole load if any certificate in the file fails to convert, which is
right for a file a consumer curated and wrong for 150 certificates shipped by
a distribution — one odd encoding would leave a program with no trust anchors
rather than 149. This crate converts entries individually and keeps the ones
that work, and `from_system_with_report` says how many it had to drop so the
degradation is visible rather than silent.

## Platform backend status

The macOS and Windows backends are compiled and run on `macos-latest` and
`windows-latest` runners on every change to this crate: `from_system` reports
`Source::Native` and returns a non-empty anchor set on both, read through
Keychain trust settings and through CryptoAPI's `ROOT` store respectively.

What that does not establish:

- iOS and Android are unverified. iOS shares this crate's Apple path but not
  its entitlements, and no runner exists for either.
- The Windows backend does not consult the `DISALLOWED` store, so an
  administrator's explicit distrust is not subtracted. The Apple backend does
  honour `Deny`.
- Anchor sets are unmeasured. A runner's trust store is not a user's, so no
  claim is made about how many anchors either backend returns, in what order,
  or which it rejects.

## License

Apache-2.0 OR MIT
