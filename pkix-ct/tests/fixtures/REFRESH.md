# Google CT log-list fixtures

Refresh with:

    base=https://www.gstatic.com/ct/log_list/v3
    curl -sSf -o google-log-list.json   "$base/log_list.json"
    curl -sSf -o google-log-list.sig    "$base/log_list.sig"
    curl -sSf "$base/log_list_pubkey.pem" \
      | openssl pkey -pubin -outform DER -out google-log-list-pubkey.der

All three must be fetched together: the signature covers the exact bytes of
that `log_list.json`, so a mismatched pair fails verification and the
`google_signature_verifies` test will say so.

Sanity-check a refresh independently of this crate before committing it:

    openssl dgst -sha256 \
      -verify <(openssl pkey -pubin -inform DER \
                 -in google-log-list-pubkey.der -pubout) \
      -signature google-log-list.sig google-log-list.json

Google rotates the list on the order of weeks, so these will go stale. That
is fine: the tests assert the signature verifies and that tampering is
caught, neither of which depends on the list being current. The one thing
that would break them is Google rotating the *signing key*, which is rare
and would require refetching the key here.
