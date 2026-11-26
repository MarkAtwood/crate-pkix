//! RFC 5280 §6.1 certificate-policy processing on the RFC 9618 policy graph.
//!
//! RFC 5280 describes `valid_policy_tree` as a tree in which the same policy
//! may appear many times at one depth, once per path from the root. With
//! policy mappings the number of such copies grows exponentially in the
//! chain length (CVE-2023-0464 and relatives). RFC 9618 replaces the tree
//! with a directed acyclic graph that has at most one node per
//! `(depth, valid_policy)`; a node records the set of its parents instead of
//! being copied once per parent. The set of valid policies, and therefore
//! every validation outcome, is unchanged (RFC 9618 §3), while the graph size
//! is linear in the total size of the certificates' policy extensions.
//!
//! [`PolicyGraph`] stores the graph level by level. Level 0 holds only the
//! synthetic `anyPolicy` root; level `d` holds the nodes created for path
//! certificate `d` (1 = the certificate issued by the trust anchor). Because
//! nodes are unique per level, a parent is identified by its `valid_policy`
//! alone, which keeps the parent links valid while levels are pruned.
//!
//! The graph never holds the RFC's NULL state itself: every mutating method
//! returns `true` when the graph has become NULL (no node at the deepest
//! level), and the caller then drops it (`policy_tree = None`).

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, collections::BTreeSet, vec::Vec};
#[cfg(feature = "std")]
use std::{collections::BTreeMap, collections::BTreeSet, vec::Vec};

use der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::certpolicy::{CertificatePolicies, PolicyQualifierInfo};
use x509_cert::ext::pkix::PolicyMappings;

use crate::{PolicyTreeNode, OID_ANY_POLICY};

/// One node of the policy graph (RFC 9618 §4, `valid_policy_graph`).
///
/// # Qualifier handling
///
/// `qualifiers` is the RFC 5280 §6.1.2(a) `qualifier_set`, kept in the
/// upstream `PolicyQualifierInfo` form without decoding the `Any` value:
/// RFC 5280 §6.1.2(a) leaves qualifier processing to the application, so
/// path validation must not gate on qualifier contents. Sources:
/// - §6.1.3(d)(1): the current certificate's `PolicyInformation` entry for
///   this policy.
/// - §6.1.3(d)(2) and §6.1.4(b)(1): the current certificate's `anyPolicy`
///   entry.
/// - §6.1.5(g)(iii)(3): the deleted leaf-level `anyPolicy` node.
/// - The synthetic root has none.
#[derive(Clone, Debug)]
struct PolicyNode {
    /// The policy OID this node represents; unique within its level.
    valid_policy: ObjectIdentifier,
    /// Policies in the next certificate that are consistent with this node.
    /// `{valid_policy}` unless replaced by a §6.1.4(b)(1) mapping.
    expected_policy_set: Vec<ObjectIdentifier>,
    /// Policy qualifiers attached to this node (see the struct rustdoc).
    qualifiers: Vec<PolicyQualifierInfo>,
    /// `valid_policy` of every parent node one level up. Empty only for the
    /// root. A node's parents are either exactly `{anyPolicy}` or a set of
    /// non-`anyPolicy` nodes, because an `anyPolicy` node's
    /// `expected_policy_set` is always `{anyPolicy}` (mappings never name
    /// `anyPolicy`, §6.1.4(a)).
    parents: Vec<ObjectIdentifier>,
}

impl PolicyNode {
    fn new(
        valid_policy: ObjectIdentifier,
        qualifiers: Vec<PolicyQualifierInfo>,
        parents: Vec<ObjectIdentifier>,
    ) -> Self {
        Self {
            valid_policy,
            expected_policy_set: vec![valid_policy],
            qualifiers,
            parents,
        }
    }

    /// Whether this node is a child of an `anyPolicy` node, i.e. a member of
    /// the §6.1.5(g)(iii) `valid_policy_node_set` (when it is not itself
    /// `anyPolicy`).
    fn has_any_policy_parent(&self) -> bool {
        self.parents.contains(&OID_ANY_POLICY)
    }
}

/// The RFC 9618 `valid_policy_graph`, one `Vec` of nodes per depth.
#[derive(Clone, Debug)]
pub(crate) struct PolicyGraph {
    levels: Vec<Vec<PolicyNode>>,
}

/// Qualifiers attached to the certificate's `anyPolicy` entry, or none.
pub(crate) fn any_policy_qualifiers(cp: &CertificatePolicies) -> Vec<PolicyQualifierInfo> {
    cp.0.iter()
        .find(|pi| pi.policy_identifier == OID_ANY_POLICY)
        .and_then(|pi| pi.policy_qualifiers.clone())
        .unwrap_or_default()
}

impl PolicyGraph {
    /// §6.1.2(a): a single `anyPolicy` root at depth 0.
    pub(crate) fn new() -> Self {
        Self {
            levels: vec![vec![PolicyNode::new(
                OID_ANY_POLICY,
                Vec::new(),
                Vec::new(),
            )]],
        }
    }

    /// Number of certificates processed so far.
    fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    fn deepest(&self) -> &[PolicyNode] {
        self.levels.last().map_or(&[][..], Vec::as_slice)
    }

    fn deepest_mut(&mut self) -> &mut Vec<PolicyNode> {
        // `levels` always holds at least the root level.
        let last = self.levels.len() - 1;
        &mut self.levels[last]
    }

    /// §6.1.3(d) for the next certificate: add a level built from its
    /// certificatePolicies extension, then prune (§6.1.3(d)(3)).
    ///
    /// `may_expand_any_policy` is the §6.1.3(d)(2) condition
    /// (`inhibit_anyPolicy > 0`, or a self-issued certificate that is not the
    /// leaf). Returns `true` when the graph has become NULL.
    pub(crate) fn add_certificate_policies(
        &mut self,
        cp: &CertificatePolicies,
        may_expand_any_policy: bool,
    ) -> bool {
        let parents = self.deepest();
        // For each expected policy of the parent level, the parents that
        // expect it. A child for policy P links to exactly these parents
        // (§6.1.3(d)(1)(i) and (d)(2), merged per RFC 9618).
        let mut expecting: BTreeMap<ObjectIdentifier, Vec<ObjectIdentifier>> = BTreeMap::new();
        for parent in parents {
            for ep in &parent.expected_policy_set {
                expecting.entry(*ep).or_default().push(parent.valid_policy);
            }
        }
        let any_parent = parents.iter().any(|p| p.valid_policy == OID_ANY_POLICY);

        let mut level: Vec<PolicyNode> = Vec::new();
        let mut present: BTreeSet<ObjectIdentifier> = BTreeSet::new();
        let mut asserts_any_policy = false;

        // (d)(1): each asserted policy other than anyPolicy. A policy listed
        // twice (forbidden by §4.2.1.4) keeps its first entry.
        for pi in &cp.0 {
            let p = pi.policy_identifier;
            if p == OID_ANY_POLICY {
                asserts_any_policy = true;
                continue;
            }
            if present.contains(&p) {
                continue;
            }
            let node_parents = match expecting.get(&p) {
                // (d)(1)(i): every parent whose expected_policy_set has P.
                Some(ps) => ps.clone(),
                // (d)(1)(ii): no such parent, but an anyPolicy parent.
                None if any_parent => vec![OID_ANY_POLICY],
                None => continue,
            };
            let qualifiers = pi.policy_qualifiers.clone().unwrap_or_default();
            level.push(PolicyNode::new(p, qualifiers, node_parents));
            present.insert(p);
        }

        // (d)(2): anyPolicy asserted and allowed: every expected policy of
        // the parent level that has no child yet gets one (including
        // anyPolicy itself, from an anyPolicy parent).
        if asserts_any_policy && may_expand_any_policy {
            let ap_q = any_policy_qualifiers(cp);
            for parent in parents {
                for ep in &parent.expected_policy_set {
                    if present.insert(*ep) {
                        let node_parents = expecting.get(ep).cloned().unwrap_or_default();
                        level.push(PolicyNode::new(*ep, ap_q.clone(), node_parents));
                    }
                }
            }
        }

        self.levels.push(level);
        // (d)(3)
        self.prune_above_deepest();
        self.deepest().is_empty()
    }

    /// §6.1.4(b) for the certificate just added by
    /// [`add_certificate_policies`][Self::add_certificate_policies].
    ///
    /// With `mapping_allowed` (`policy_mapping > 0`, §6.1.4(b)(1)) each
    /// issuerDomainPolicy node's expected_policy_set becomes the set of all
    /// subjectDomainPolicy values mapped from it, regardless of the order
    /// of the mappings in the extension; an issuerDomainPolicy without a
    /// node is synthesized under the anyPolicy node when the level has one.
    /// Otherwise (§6.1.4(b)(2)) issuerDomainPolicy nodes are deleted and the
    /// graph pruned. The caller has already rejected mappings to or from
    /// anyPolicy (§6.1.4(a)). Returns `true` when the graph has become NULL.
    pub(crate) fn apply_policy_mappings(
        &mut self,
        pm: &PolicyMappings,
        mapping_allowed: bool,
        any_policy_qualifiers: &[PolicyQualifierInfo],
    ) -> bool {
        // Group subjectDomainPolicy values by issuerDomainPolicy, keeping
        // first-seen order for deterministic output.
        let mut order: Vec<ObjectIdentifier> = Vec::new();
        let mut targets: BTreeMap<ObjectIdentifier, Vec<ObjectIdentifier>> = BTreeMap::new();
        for m in &pm.0 {
            let sdps = targets.entry(m.issuer_domain_policy).or_insert_with(|| {
                order.push(m.issuer_domain_policy);
                Vec::new()
            });
            if !sdps.contains(&m.subject_domain_policy) {
                sdps.push(m.subject_domain_policy);
            }
        }

        if mapping_allowed {
            let level = self.deepest_mut();
            let has_any = level.iter().any(|n| n.valid_policy == OID_ANY_POLICY);
            for idp in order {
                let sdps = targets.remove(&idp).unwrap_or_default();
                if let Some(node) = level.iter_mut().find(|n| n.valid_policy == idp) {
                    node.expected_policy_set = sdps;
                } else if has_any {
                    // §6.1.4(b)(1): child of the depth i-1 anyPolicy node
                    // (the parent of this level's anyPolicy node).
                    let mut node =
                        PolicyNode::new(idp, any_policy_qualifiers.to_vec(), vec![OID_ANY_POLICY]);
                    node.expected_policy_set = sdps;
                    level.push(node);
                }
            }
            false
        } else {
            self.deepest_mut()
                .retain(|n| !targets.contains_key(&n.valid_policy));
            self.prune_above_deepest();
            self.deepest().is_empty()
        }
    }

    /// §6.1.5(g)(iii): intersect with a user-initial-policy-set that is not
    /// any-policy (the caller handles §6.1.5(g)(ii)). Returns `true` when the
    /// graph has become NULL.
    pub(crate) fn intersect_user_policy_set(&mut self, user_set: &[ObjectIdentifier]) -> bool {
        let n = self.depth();

        // (iii)(1)-(2): delete every valid_policy_node_set member (a child of
        // anyPolicy) that is neither anyPolicy nor in the user set, then every
        // node left without a parent. One top-down pass suffices because a
        // node's parents are always one level up.
        for d in 1..=n {
            let (above, rest) = self.levels.split_at_mut(d);
            let alive: BTreeSet<ObjectIdentifier> =
                above[d - 1].iter().map(|p| p.valid_policy).collect();
            rest[0].retain_mut(|node| {
                if node.has_any_policy_parent()
                    && node.valid_policy != OID_ANY_POLICY
                    && !user_set.contains(&node.valid_policy)
                {
                    return false;
                }
                node.parents.retain(|p| alive.contains(p));
                !node.parents.is_empty()
            });
        }

        // (iii)(3): a leaf-level anyPolicy node stands for every policy; turn
        // it into one node per user policy not already in valid_policy_node_set.
        if let Some(pos) = self.levels[n]
            .iter()
            .position(|nd| nd.valid_policy == OID_ANY_POLICY)
        {
            let any_leaf = self.levels[n].remove(pos);
            let vpns: BTreeSet<ObjectIdentifier> = self
                .levels
                .iter()
                .flatten()
                .filter(|nd| nd.has_any_policy_parent())
                .map(|nd| nd.valid_policy)
                .collect();
            for p in user_set {
                if vpns.contains(p) {
                    continue;
                }
                let level = &mut self.levels[n];
                if let Some(existing) = level.iter_mut().find(|nd| nd.valid_policy == *p) {
                    // Already present under non-anyPolicy parents: unique
                    // per level, so add the anyPolicy parent to that node.
                    existing.parents.push(OID_ANY_POLICY);
                } else {
                    level.push(PolicyNode::new(
                        *p,
                        any_leaf.qualifiers.clone(),
                        vec![OID_ANY_POLICY],
                    ));
                }
            }
        }

        // (iii)(4)
        self.prune_above_deepest();
        self.deepest().is_empty()
    }

    /// §6.1.3(d)(3): repeatedly delete nodes above the deepest level that
    /// have no children. The root is never deleted here; the caller drops
    /// the whole graph once the deepest level is empty.
    fn prune_above_deepest(&mut self) {
        for d in (1..self.levels.len().saturating_sub(1)).rev() {
            let referenced: BTreeSet<ObjectIdentifier> = self.levels[d + 1]
                .iter()
                .flat_map(|c| c.parents.iter().copied())
                .collect();
            self.levels[d].retain(|n| referenced.contains(&n.valid_policy));
        }
    }

    /// Flatten into the public [`PolicyTreeNode`] form, root first, then
    /// level by level in creation order.
    pub(crate) fn into_public(self) -> Vec<PolicyTreeNode> {
        self.levels
            .into_iter()
            .enumerate()
            .flat_map(|(depth, level)| {
                level.into_iter().map(move |n| PolicyTreeNode {
                    depth,
                    valid_policy: n.valid_policy,
                    expected_policy_set: n.expected_policy_set,
                    qualifiers: n.qualifiers,
                    parent_policies: n.parents,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::ext::pkix::certpolicy::PolicyInformation;

    const P1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.1");
    const P2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.2");
    const SHARED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99.9");

    fn policies(oids: &[ObjectIdentifier]) -> CertificatePolicies {
        CertificatePolicies(
            oids.iter()
                .map(|o| PolicyInformation {
                    policy_identifier: *o,
                    policy_qualifiers: None,
                })
                .collect(),
        )
    }

    /// At most one node per policy OID at any depth.
    ///
    /// RFC 9618 §6.1.3(d) builds children per expected policy of the
    /// parent level, and two parents can expect the same policy — which
    /// is ordinary after policy mappings, since §6.1.4(b)(1) rewrites an
    /// `expected_policy_set` to the mapped values and two issuer domain
    /// policies may map to one subject domain policy. A second node for
    /// the same OID at the same depth is not a cosmetic duplicate: nodes
    /// carry parent lists, and the §6.1.5 authorities-set and
    /// user-policy intersection walk them, so a duplicate double-counts the
    /// same policy and can let an intersection succeed on a policy that
    /// should have been pruned.
    ///
    /// The anyPolicy expansion in §6.1.3(d)(2) is where this surfaced: it
    /// once tested against a snapshot of the policies already present,
    /// taken before the loop over parents, so a policy added for the
    /// first parent was invisible when the second parent expected it too.
    #[test]
    fn any_policy_expansion_never_duplicates_a_policy_at_one_depth() {
        let mut g = PolicyGraph::new();

        // Depth 1: two concrete policies under the anyPolicy root.
        assert!(!g.add_certificate_policies(&policies(&[P1, P2]), true));

        // Make both nodes expect the same policy, which is what policy
        // mappings produce when two issuer domain policies map to one
        // subject domain policy.
        let level = g.levels.last_mut().expect("depth 1 exists");
        assert_eq!(level.len(), 2, "two policies asserted, two nodes");
        for node in level.iter_mut() {
            node.expected_policy_set = vec![SHARED];
        }

        // Depth 2: a certificate asserting anyPolicy, so (d)(2) expands
        // every expected policy of the parent level. Both parents expect
        // SHARED, so the expansion visits it twice.
        assert!(!g.add_certificate_policies(&policies(&[OID_ANY_POLICY]), true));

        let deepest = g.levels.last().expect("depth 2 exists");
        let mut seen = BTreeSet::new();
        for node in deepest {
            assert!(
                seen.insert(node.valid_policy),
                "policy {} has more than one node at this depth: {deepest:#?}",
                node.valid_policy
            );
        }
        assert_eq!(
            deepest.len(),
            1,
            "both parents expect only SHARED, so the level is one node: {deepest:#?}"
        );

        // And the single node records both parents, which is the reason
        // one node is correct rather than merely tidier: §6.1.3(d)(1)(i)
        // links a child to every parent whose expected_policy_set has it.
        assert_eq!(
            deepest[0].parents.len(),
            2,
            "the one node must list both parents: {deepest:#?}"
        );
    }
}
