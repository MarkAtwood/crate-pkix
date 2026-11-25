//! End-to-end MTA-STS policy discovery for one or more domains.
//!
//! Shows how the three crates compose, which is otherwise spread across their
//! separate documentation:
//!
//! 1. `pkix-mta-sts-resolver` looks up the `_mta-sts` TXT record (§3.1)
//! 2. `pkix-mta-sts` decides whether a fetch is needed (§3.3, §5.1)
//! 3. `pkix-mta-sts-http` fetches the policy and records the outcome (§3.3)
//! 4. `pkix-mta-sts` says which policy to apply, and to which MX hosts
//!
//! Run with:
//!
//! ```sh
//! cargo run -p pkix-mta-sts-http --features client-ureq \
//!     --example discover -- gmail.com outlook.com
//! ```
//!
//! Note the second pass over each domain: it shows the cache working, which
//! is the part that actually protects anything. MTA-STS's TXT record is
//! unsigned and the policy arrives over ordinary HTTPS, so first contact is
//! trust-on-first-use — the protection comes from holding the policy across
//! the moment an attacker shows up.

use std::time::{SystemTime, UNIX_EPOCH};

use pkix_mta_sts::{
    plan_with_store, policy_to_apply, DiscoveryConfig, DiscoveryPlan, InMemoryPolicyStore,
    PolicyStore as _,
};
use pkix_mta_sts_http::{fetch_and_record, PolicyFetcher};
use pkix_mta_sts_resolver::MtaStsResolver;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domains: Vec<String> = std::env::args().skip(1).collect();
    if domains.is_empty() {
        eprintln!("usage: discover <domain>...");
        return Ok(());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let store = InMemoryPolicyStore::new();
    let resolver = MtaStsResolver::from_system()?;
    let fetcher = PolicyFetcher::new();
    let config = DiscoveryConfig::default();

    for pass in 1..=2 {
        println!("\n--- pass {pass} ---");
        for domain in &domains {
            // 1. The TXT lookup. A failure is passed through as_txt_error
            //    rather than translated, so §3.1's rule that it must not
            //    discard a cached policy is applied by plan_with_store.
            let txt = resolver.lookup(domain).await;
            let txt_ref = txt.as_ref().map_err(|e| e.as_txt_error());

            // 2. What to do, given the cache and §3.3's backoff.
            let decided = plan_with_store(&store, domain, txt_ref, now, &config);

            // 3. Fetch if wanted, recording the outcome either way.
            let fetched = if matches!(
                decided,
                DiscoveryPlan::Fetch | DiscoveryPlan::RefreshButUseCachedIfUnavailable
            ) {
                let id = txt.as_ref().map(|r| r.id()).unwrap_or("");
                match fetch_and_record(&fetcher, &store, domain, id, now) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        println!("  {domain}: {decided:?}, fetch failed: {e}");
                        None
                    }
                }
            } else {
                None
            };

            // 4. Which policy applies, falling back to the cache per §3.3.
            let cached = store.get(domain);
            match policy_to_apply(fetched.as_ref(), cached.as_ref(), now) {
                Some(policy) => {
                    println!(
                        "  {domain}: {decided:?} -> mode={:?} max_age={} mx={:?}",
                        policy.mode(),
                        policy.max_age(),
                        policy.mx_patterns()
                    );
                    // And what it says about a candidate MX.
                    if let Some(first) = policy.mx_patterns().first() {
                        let host = first.trim_start_matches("*.");
                        let probe = if first.starts_with("*.") {
                            format!("mx1.{host}")
                        } else {
                            host.to_owned()
                        };
                        println!("      {probe} -> {:?}", policy.evaluate(&probe));
                    }
                }
                None => println!("  {domain}: {decided:?} -> no policy applies"),
            }
        }
    }

    println!("\ncached policies: {}", store.policy_count());
    Ok(())
}
