//! A sub-environment's policy bundle (SPEC.md "The egress proxy", "Policy bundle"):
//! JSON signed by the customer's policy key with a detached JWS, verified by the cell
//! before it admits a sandbox under it.
//!
//! ```json
//! { "v": 1, "env": "staging", "subenv": "a", "version": 7, "expires": 1793102400,
//!   "sandbox": { "default": { "cpu": 1, "memory": 2 },
//!                "max": { "cpu": 7, "memory": 27, "timeout": 86400 } },
//!   "resolvers": [ { "ip": "1.1.1.1", "name": "cloudflare-dns.com" } ],
//!   "templates": [ "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" ],
//!   "destinations": [
//!     { "host": "api.openai.com", "port": 443, "paths": ["/v1/"],
//!       "adapter": { "type": "bearer", "header": "authorization", "credential": "openai" } },
//!     { "host": "*.example.com", "port": 443 },
//!     { "host": "pinned.example.net", "port": 443, "passthrough": true } ] }
//! ```
//!
//! [`Policy::verify`] checks the signature, the environment and sub-environment, the
//! expiry and every destination, and refuses the whole bundle on any failure: an unknown
//! field or adapter type, a wildcard or passthrough destination with an adapter, a path
//! rule on a passthrough destination, a template digest that is malformed or listed
//! twice. Default deny: no destinations allow nothing.
//!
//! The egress proxy runs in its own process, which holds no policy key: the agent hands
//! it the bytes of a policy it verified ([`Policy::bytes`]) and the proxy rebuilds the
//! policy with [`Policy::parse_trusted`], which skips the signature, scope and expiry.
//!
//! Hosts are matched by [`HostPattern`]: a name, an IPv4 address, `*` (any host) or
//! `*.example.com` (exactly one more label: `api.example.com`, not `example.com`,
//! `a.b.example.com` or `evil-example.com`).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use serde::Deserialize;

use crate::cred::{AdapterType, CredName};
use crate::ids::{EnvId, SubenvId};
use crate::jws::{self, JwsError, TrustedKey};
use crate::sandbox::{Limits, LimitsError, Size};
use crate::template::Digest;

/// The DNS-over-TLS resolvers the proxy uses when a bundle names none (the image's
/// pinned set).
pub const DEFAULT_RESOLVERS: [(Ipv4Addr, &str); 2] = [
    (Ipv4Addr::new(1, 1, 1, 1), "cloudflare-dns.com"),
    (Ipv4Addr::new(8, 8, 8, 8), "dns.google"),
];

/// A lower-case DNS name: labels of 1-63 of `a-z`, `0-9`, `-`, `_`, at most 253
/// characters, no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a host name")]
pub struct HostNameError(pub String);

impl HostName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for HostName {
    type Err = HostNameError;

    /// Accepts any case and one trailing dot (as SNI, Host headers and DNS questions
    /// carry them) and stores the lower-case form.
    fn from_str(s: &str) -> Result<Self, HostNameError> {
        let name = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        };
        if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
            return Err(HostNameError(s.to_owned()));
        }
        Ok(Self(name))
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a connection is going, as the proxy learned it (SNI, Host header, CONNECT
/// target or DNS question): a name or an IPv4 literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Name(HostName),
    Ip(Ipv4Addr),
}

impl FromStr for Host {
    type Err = HostNameError;

    fn from_str(s: &str) -> Result<Self, HostNameError> {
        match s.parse::<Ipv4Addr>() {
            Ok(ip) => Ok(Host::Ip(ip)),
            Err(_) => s.parse().map(Host::Name),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Name(n) => n.fmt(f),
            Host::Ip(ip) => ip.fmt(f),
        }
    }
}

/// A destination's `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// One name.
    Name(HostName),
    /// One IPv4 address (the proxy still refuses addresses that are not public).
    Ip(Ipv4Addr),
    /// `*.suffix`: a name with exactly one label before `suffix`.
    OneLevel(HostName),
    /// `*`: any host.
    Any,
}

impl HostPattern {
    /// Whether `host` matches.
    pub fn matches(&self, host: &Host) -> bool {
        match (self, host) {
            (HostPattern::Any, _) => true,
            (HostPattern::Name(n), Host::Name(h)) => n == h,
            (HostPattern::Ip(ip), Host::Ip(h)) => ip == h,
            (HostPattern::OneLevel(suffix), Host::Name(h)) => h
                .as_str()
                .strip_suffix(suffix.as_str())
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            _ => false,
        }
    }

    /// A wildcard (`*` or `*.suffix`) rather than one named host.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, HostPattern::OneLevel(_) | HostPattern::Any)
    }

    /// Lower ranks win: a named host before `*.suffix` before `*`.
    fn rank(&self) -> u8 {
        match self {
            HostPattern::Name(_) | HostPattern::Ip(_) => 0,
            HostPattern::OneLevel(_) => 1,
            HostPattern::Any => 2,
        }
    }
}

impl FromStr for HostPattern {
    type Err = HostNameError;

    fn from_str(s: &str) -> Result<Self, HostNameError> {
        if s == "*" {
            return Ok(HostPattern::Any);
        }
        if let Some(suffix) = s.strip_prefix("*.") {
            return suffix.parse().map(HostPattern::OneLevel);
        }
        if s.contains('*') {
            return Err(HostNameError(s.to_owned()));
        }
        Ok(match s.parse::<Host>()? {
            Host::Name(n) => HostPattern::Name(n),
            Host::Ip(ip) => HostPattern::Ip(ip),
        })
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Name(n) => n.fmt(f),
            HostPattern::Ip(ip) => ip.fmt(f),
            HostPattern::OneLevel(s) => write!(f, "*.{s}"),
            HostPattern::Any => f.write_str("*"),
        }
    }
}

/// An HTTP header name, lower case (`authorization`, `x-api-key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for HeaderName {
    type Err = BundleError;

    fn from_str(s: &str) -> Result<Self, BundleError> {
        // RFC 9110 tchar.
        let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
        if s.is_empty() || s.len() > 128 || !s.bytes().all(tchar) {
            return Err(BundleError::Invalid(format!("header name {s:?}")));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }
}

/// How a destination's credential is substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterKind {
    /// Every placeholder in header `header` (`Authorization: Bearer clovelly://cred/x`,
    /// `x-api-key: clovelly://cred/x`) is replaced by the secret.
    Bearer { header: HeaderName },
    /// `Authorization: Basic base64(user:pass)`: a placeholder inside the decoded
    /// `user:pass` is replaced and the value re-encoded.
    Basic,
    /// A placeholder in query parameter `param` (raw or percent-encoded) is replaced by
    /// the percent-encoded secret.
    Query { param: String },
}

impl AdapterKind {
    pub fn kind(&self) -> AdapterType {
        match self {
            AdapterKind::Bearer { .. } => AdapterType::Bearer,
            AdapterKind::Basic => AdapterType::Basic,
            AdapterKind::Query { .. } => AdapterType::Query,
        }
    }
}

/// A destination's credential adapter: how, and which credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub kind: AdapterKind,
    pub credential: CredName,
}

/// What the proxy does with a destination's traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// TLS is terminated with the in-cell CA (port 80 is plain HTTP); requests are
    /// checked and, with an adapter, rewritten.
    Inspect { adapter: Option<Adapter> },
    /// TLS is relayed untouched to the named host: no substitution, no path rules.
    Passthrough,
}

/// One allowed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: HostPattern,
    pub port: u16,
    /// Path prefixes a request must start with; empty allows any path.
    pub paths: Vec<String>,
    pub mode: Mode,
}

impl Destination {
    pub fn adapter(&self) -> Option<&Adapter> {
        match &self.mode {
            Mode::Inspect { adapter } => adapter.as_ref(),
            Mode::Passthrough => None,
        }
    }

    pub fn is_passthrough(&self) -> bool {
        self.mode == Mode::Passthrough
    }

    /// Whether a request path is allowed: no path rules, or it starts with one.
    pub fn allows_path(&self, path: &str) -> bool {
        self.paths.is_empty() || self.paths.iter().any(|p| path.starts_with(p.as_str()))
    }
}

/// A DNS-over-TLS resolver: its address and the name its certificate carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub ip: Ipv4Addr,
    pub name: HostName,
}

/// What the policy says about a connection to `host:port`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// A destination naming this host.
    Named(&'a Destination),
    /// A wildcard destination (`*` or `*.suffix`): never substituted.
    Wildcard(&'a Destination),
    Denied,
}

impl<'a> Verdict<'a> {
    pub fn destination(self) -> Option<&'a Destination> {
        match self {
            Verdict::Named(d) | Verdict::Wildcard(d) => Some(d),
            Verdict::Denied => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("policy signature: {0}")]
    Signature(#[from] JwsError),
    #[error("policy bundle JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy bundle is for {got}, this cell serves {want}")]
    WrongScope { want: String, got: String },
    #[error("policy bundle version {version} expired at {expires}")]
    Expired { version: u64, expires: u64 },
    #[error("policy bundle version {got} is older than version {have}, already in force")]
    Rollback { have: u64, got: u64 },
    #[error("policy bundle: {0}")]
    Invalid(String),
    #[error("policy bundle template {entry:?} {why}")]
    Templates { entry: String, why: &'static str },
    #[error(transparent)]
    Limits(#[from] LimitsError),
}

impl BundleError {
    /// A short name for logs and the `POLICY_REFUSED` detail.
    pub fn kind(&self) -> &'static str {
        match self {
            BundleError::Signature(_) => "signature",
            BundleError::Json(_) => "json",
            BundleError::WrongScope { .. } => "scope",
            BundleError::Expired { .. } => "expired",
            BundleError::Rollback { .. } => "rollback",
            BundleError::Invalid(_) => "invalid",
            BundleError::Templates { .. } => "templates",
            BundleError::Limits(_) => "limits",
        }
    }
}

/// A verified policy bundle.
#[derive(Debug, Clone)]
pub struct Policy {
    pub env: EnvId,
    pub subenv: SubenvId,
    pub version: u64,
    pub expires: SystemTime,
    pub limits: Limits,
    pub resolvers: Vec<Resolver>,
    pub destinations: Vec<Destination>,
    /// The templates a cell of the sub-environment pre-pulls into its cache (boot step
    /// 7), each listed once.
    pub templates: Vec<Digest>,
    /// SHA-256 of the bundle bytes as signed (the receipt's `policy_hash`).
    pub hash: [u8; 32],
    /// The bundle bytes as signed.
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u32,
    env: String,
    subenv: String,
    version: u64,
    expires: u64,
    // Read by `Limits::from_bundle`; named here so `deny_unknown_fields` accepts it.
    #[serde(default, rename = "sandbox")]
    _sandbox: Option<serde_json::Value>,
    #[serde(default)]
    resolvers: Vec<WireResolver>,
    destinations: Vec<WireDestination>,
    #[serde(default)]
    templates: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResolver {
    ip: Ipv4Addr,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDestination {
    host: String,
    port: u16,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    passthrough: bool,
    adapter: Option<WireAdapter>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum WireAdapter {
    Bearer {
        #[serde(default = "authorization")]
        header: String,
        credential: String,
    },
    Basic {
        credential: String,
    },
    Query {
        param: String,
        credential: String,
    },
}

fn authorization() -> String {
    "authorization".to_owned()
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What [`Policy::parse`] checks besides the bundle's own consistency.
enum Scope<'a> {
    /// A cell of `env`/`subenv` at `now`: the bundle must name them and be unexpired.
    Cell { env: &'a EnvId, subenv: &'a SubenvId, now: SystemTime },
    /// Bytes of a policy the agent already verified: neither.
    Verified,
}

impl Policy {
    /// Verifies `bundle` against its detached JWS `sig` under the customer's policy key
    /// and parses it for a cell of `env`/`subenv` at `now`. `placeable` is the cell's
    /// placeable capacity, the maximum sandbox size when the bundle names none.
    pub fn verify(
        bundle: &[u8],
        sig: &str,
        key: &TrustedKey,
        env: &EnvId,
        subenv: &SubenvId,
        now: SystemTime,
        placeable: Size,
    ) -> Result<Self, BundleError> {
        jws::verify_detached(sig, bundle, std::slice::from_ref(key))?;
        Self::parse(bundle, placeable, Scope::Cell { env, subenv, now })
    }

    /// Rebuilds a policy from [`Policy::bytes`] of one already verified, in a process
    /// that holds no policy key (the egress proxy): no signature, scope or expiry check,
    /// since a running sandbox keeps its policy past the bundle's `expires`. `ceiling`
    /// is the verifying side's `limits.max`, which reproduces its limits exactly. Never
    /// call it on bytes that did not come from a verified policy.
    pub fn parse_trusted(bundle: &[u8], ceiling: Size) -> Result<Self, BundleError> {
        Self::parse(bundle, ceiling, Scope::Verified)
    }

    /// The bundle bytes as signed, for [`Policy::parse_trusted`] in another process.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn parse(bundle: &[u8], placeable: Size, scope: Scope<'_>) -> Result<Self, BundleError> {
        let w: Wire = serde_json::from_slice(bundle)?;
        if w.v != 1 {
            return Err(BundleError::Invalid(format!("unknown format version {}", w.v)));
        }
        let (env, subenv) = match scope {
            Scope::Cell { env, subenv, now } => {
                if w.env != env.as_str() || w.subenv != subenv.as_str() {
                    return Err(BundleError::WrongScope {
                        want: format!("{}/{}", env.as_str(), subenv.as_str()),
                        got: format!("{}/{}", w.env, w.subenv),
                    });
                }
                if w.expires <= unix(now) {
                    return Err(BundleError::Expired { version: w.version, expires: w.expires });
                }
                (env.clone(), subenv.clone())
            }
            Scope::Verified => {
                let invalid = |e: crate::ids::IdError| BundleError::Invalid(e.to_string());
                (w.env.parse().map_err(invalid)?, w.subenv.parse().map_err(invalid)?)
            }
        };
        let limits = Limits::from_bundle(bundle, placeable)?;
        let resolvers = w
            .resolvers
            .into_iter()
            .map(|r| {
                let name = r.name.parse().map_err(|e: HostNameError| BundleError::Invalid(e.to_string()))?;
                Ok(Resolver { ip: r.ip, name })
            })
            .collect::<Result<Vec<_>, BundleError>>()?;
        let destinations = w
            .destinations
            .into_iter()
            .map(destination)
            .collect::<Result<Vec<_>, _>>()?;
        let mut templates: Vec<Digest> = Vec::with_capacity(w.templates.len());
        for entry in w.templates {
            let Ok(t) = entry.parse::<Digest>() else {
                return Err(BundleError::Templates { entry, why: "is not 64 lowercase hex characters" });
            };
            if templates.contains(&t) {
                return Err(BundleError::Templates { entry, why: "is listed twice" });
            }
            templates.push(t);
        }
        Ok(Self {
            env,
            subenv,
            version: w.version,
            expires: UNIX_EPOCH + Duration::from_secs(w.expires),
            limits,
            resolvers,
            destinations,
            templates,
            hash: digest::digest(&digest::SHA256, bundle)
                .as_ref()
                .try_into()
                .expect("SHA-256 is 32 bytes"),
            bytes: bundle.to_vec(),
        })
    }

    /// Refuses a bundle older than the version already in force (a replayed bundle).
    pub fn check_succeeds(&self, current: Option<&Policy>) -> Result<(), BundleError> {
        match current {
            Some(c) if self.version < c.version => Err(BundleError::Rollback {
                have: c.version,
                got: self.version,
            }),
            _ => Ok(()),
        }
    }

    /// The destination for a connection to `host:port`: a named host first, then
    /// `*.suffix`, then `*`; denied if none matches.
    pub fn decide(&self, host: &Host, port: u16) -> Verdict<'_> {
        let best = self
            .destinations
            .iter()
            .filter(|d| d.port == port && d.host.matches(host))
            .min_by_key(|d| d.host.rank());
        match best {
            Some(d) if d.host.is_wildcard() => Verdict::Wildcard(d),
            Some(d) => Verdict::Named(d),
            None => Verdict::Denied,
        }
    }

    /// Whether the proxy's DNS answers for `name`: some destination, on any port,
    /// matches it.
    pub fn resolves(&self, name: &HostName) -> bool {
        let host = Host::Name(name.clone());
        self.destinations.iter().any(|d| d.host.matches(&host))
    }

    /// The resolvers to use: the bundle's, or the image's pinned set.
    pub fn resolvers(&self) -> Vec<Resolver> {
        if !self.resolvers.is_empty() {
            return self.resolvers.clone();
        }
        DEFAULT_RESOLVERS
            .iter()
            .map(|(ip, name)| Resolver {
                ip: *ip,
                name: name.parse().expect("the pinned resolver names are valid"),
            })
            .collect()
    }

    /// The credentials the policy's adapters name, each with the one destination
    /// (named host) it may be released to and its adapter type.
    pub fn credentials(&self) -> Vec<(CredName, HostName, AdapterType)> {
        let mut out: Vec<_> = self
            .destinations
            .iter()
            .filter_map(|d| match (&d.host, d.adapter()) {
                (HostPattern::Name(h), Some(a)) => Some((a.credential.clone(), h.clone(), a.kind.kind())),
                _ => None,
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Lower-case hex of [`Policy::hash`].
    pub fn hash_hex(&self) -> String {
        crate::hex(&self.hash)
    }
}

fn destination(w: WireDestination) -> Result<Destination, BundleError> {
    let host: HostPattern = w.host.parse().map_err(|e: HostNameError| BundleError::Invalid(e.to_string()))?;
    if w.port == 0 {
        return Err(BundleError::Invalid(format!("{host}: port 0")));
    }
    if let Some(p) = w.paths.iter().find(|p| !p.starts_with('/') || p.contains(['?', '#', '\\'])) {
        return Err(BundleError::Invalid(format!("{host}: path rule {p:?} must be an absolute path")));
    }
    let adapter = w.adapter.map(adapter).transpose()?;
    if adapter.is_some() {
        match &host {
            HostPattern::Name(_) => {}
            HostPattern::Ip(_) => {
                return Err(BundleError::Invalid(format!("{host}: adapters are bound to a named host")));
            }
            HostPattern::OneLevel(_) | HostPattern::Any => {
                return Err(BundleError::Invalid(format!("{host}: a wildcard destination carries no adapter")));
            }
        }
    }
    let mode = match (w.passthrough, adapter) {
        (true, Some(_)) => {
            return Err(BundleError::Invalid(format!("{host}: passthrough disables credential substitution")));
        }
        (true, None) if !w.paths.is_empty() => {
            return Err(BundleError::Invalid(format!("{host}: passthrough cannot apply path rules")));
        }
        (true, None) => Mode::Passthrough,
        (false, adapter) => Mode::Inspect { adapter },
    };
    Ok(Destination {
        host,
        port: w.port,
        paths: w.paths,
        mode,
    })
}

fn adapter(w: WireAdapter) -> Result<Adapter, BundleError> {
    let name = |c: String| c.parse::<CredName>().map_err(|e| BundleError::Invalid(e.to_string()));
    Ok(match w {
        WireAdapter::Bearer { header, credential } => Adapter {
            kind: AdapterKind::Bearer { header: header.parse()? },
            credential: name(credential)?,
        },
        WireAdapter::Basic { credential } => Adapter {
            kind: AdapterKind::Basic,
            credential: name(credential)?,
        },
        WireAdapter::Query { param, credential } => {
            if param.is_empty() || param.bytes().any(|b| b"&=#?% ".contains(&b) || b.is_ascii_control()) {
                return Err(BundleError::Invalid(format!("query parameter {param:?}")));
            }
            Adapter {
                kind: AdapterKind::Query { param },
                credential: name(credential)?,
            }
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::evidence::Spki;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    pub(crate) fn key() -> (EcdsaKeyPair, TrustedKey) {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let spki = Spki::from_der(kp.public_key().as_der().unwrap().as_ref()).unwrap();
        (kp, TrustedKey::from_spki(spki))
    }

    pub(crate) fn sign(kp: &EcdsaKeyPair, bundle: &[u8]) -> String {
        let der = kp.sign(&SystemRandom::new(), jws::signing_input(bundle).as_bytes()).unwrap();
        jws::assemble(bundle, der.as_ref(), true).unwrap()
    }

    fn ids() -> (EnvId, SubenvId) {
        ("staging".parse().unwrap(), "a".parse().unwrap())
    }

    const NOW: u64 = 1_793_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn placeable() -> Size {
        Size::new(crate::sandbox::CpuHalves(14), crate::sandbox::MemoryGib(27))
    }

    fn bundle(destinations: &str) -> String {
        format!(
            r#"{{"v":1,"env":"staging","subenv":"a","version":3,"expires":{},"destinations":{destinations}}}"#,
            NOW + 3600
        )
    }

    fn verify(kp: &EcdsaKeyPair, key: &TrustedKey, bundle: &str) -> Result<Policy, BundleError> {
        let (env, sub) = ids();
        Policy::verify(bundle.as_bytes(), &sign(kp, bundle.as_bytes()), key, &env, &sub, at(NOW), placeable())
    }

    fn host(s: &str) -> Host {
        s.parse().unwrap()
    }

    /// Criterion 13: `*.example.com` matches exactly one more label; `evil-example.com`,
    /// the bare domain and a two-level name do not match.
    #[test]
    fn wildcard_matcher_takes_exactly_one_label() {
        let p: HostPattern = "*.example.com".parse().unwrap();
        assert!(p.matches(&host("api.example.com")));
        assert!(p.matches(&host("API.Example.COM.")));
        for no in ["evil-example.com", "example.com", "a.b.example.com", "example.com.evil.net", "xexample.com"] {
            assert!(!p.matches(&host(no)), "{no}");
        }
        assert!(!p.matches(&host("10.0.0.1")));
        let any: HostPattern = "*".parse().unwrap();
        assert!(any.matches(&host("anything.at.all")) && any.matches(&host("192.0.2.1")));
        for bad in ["*example.com", "a.*.com", "**", "*.", "*.*.com", "exa mple.com", ""] {
            assert!(bad.parse::<HostPattern>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn named_hosts_beat_wildcards_and_ports_must_match() {
        let (kp, key) = key();
        let p = verify(
            &kp,
            &key,
            &bundle(
                r#"[{"host":"*","port":443},{"host":"*.example.com","port":443},
                    {"host":"api.example.com","port":443,"adapter":{"type":"bearer","credential":"ex"}},
                    {"host":"pinned.example.net","port":443,"passthrough":true}]"#,
            ),
        )
        .unwrap();
        assert!(matches!(p.decide(&host("api.example.com"), 443), Verdict::Named(d) if d.adapter().is_some()));
        assert!(matches!(p.decide(&host("www.example.com"), 443), Verdict::Wildcard(d) if d.host == "*.example.com".parse().unwrap()));
        assert!(matches!(p.decide(&host("other.org"), 443), Verdict::Wildcard(d) if d.host == HostPattern::Any));
        assert_eq!(p.decide(&host("api.example.com"), 80), Verdict::Denied);
        assert!(matches!(p.decide(&host("pinned.example.net"), 443), Verdict::Named(d) if d.is_passthrough()));
        assert_eq!(p.credentials().len(), 1);
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let (kp, key) = key();
        let p = verify(&kp, &key, &bundle("[]")).unwrap();
        assert_eq!(p.decide(&host("example.com"), 443), Verdict::Denied);
        assert!(!p.resolves(&"example.com".parse().unwrap()));
        assert_eq!(p.resolvers().len(), 2, "the pinned resolvers");
    }

    /// Criterion 10: a bad signature, a wrong env id, an expired version and an unknown
    /// adapter type are each refused.
    #[test]
    fn policy_bundle_refusals() {
        let (kp, key) = key();
        let (env, sub) = ids();
        let good = bundle(r#"[{"host":"api.example.com","port":443,"adapter":{"type":"bearer","credential":"ex"}}]"#);
        assert!(verify(&kp, &key, &good).is_ok());

        // Bad signature: signed by another key, and a valid signature over other bytes.
        let (other, _) = self::key();
        let e = verify(&other, &key, &good).unwrap_err();
        assert_eq!(e.kind(), "signature", "{e}");
        let sig = sign(&kp, good.as_bytes());
        let tampered = good.replace("api.example.com", "api.example.org");
        let e = Policy::verify(tampered.as_bytes(), &sig, &key, &env, &sub, at(NOW), placeable()).unwrap_err();
        assert_eq!(e.kind(), "signature");

        // Wrong env id and wrong sub-environment.
        for wrong in [good.replace(r#""env":"staging""#, r#""env":"prod""#), good.replace(r#""subenv":"a""#, r#""subenv":"b""#)] {
            assert_eq!(verify(&kp, &key, &wrong).unwrap_err().kind(), "scope");
        }

        // Expired version.
        let expired = good.replace(&format!("{}", NOW + 3600), &format!("{}", NOW - 1));
        assert!(matches!(verify(&kp, &key, &expired).unwrap_err(), BundleError::Expired { version: 3, .. }));

        // Unknown adapter type.
        let unknown = good.replace(r#""type":"bearer""#, r#""type":"sigv4""#);
        assert_eq!(verify(&kp, &key, &unknown).unwrap_err().kind(), "json");

        // Template digests: well formed, each once.
        let t = "ab".repeat(32);
        let listed = good.replacen('{', &format!(r#"{{"templates":["{t}"],"#), 1);
        assert_eq!(verify(&kp, &key, &listed).unwrap().templates, vec![t.parse().unwrap()]);
        assert!(verify(&kp, &key, &good).unwrap().templates.is_empty(), "absent means none");
        for bad in [format!(r#"["{t}","{t}"]"#), format!(r#"["{}"]"#, "AB".repeat(32)), r#"["abc"]"#.to_owned()] {
            let wrong = good.replacen('{', &format!(r#"{{"templates":{bad},"#), 1);
            assert_eq!(verify(&kp, &key, &wrong).unwrap_err().kind(), "templates", "{bad}");
        }

        // An older version than the one in force.
        let current = verify(&kp, &key, &good).unwrap();
        let older = verify(&kp, &key, &good.replace(r#""version":3"#, r#""version":2"#)).unwrap();
        assert!(matches!(older.check_succeeds(Some(&current)), Err(BundleError::Rollback { have: 3, got: 2 })));
        assert!(current.check_succeeds(Some(&older)).is_ok());
    }

    /// The egress proxy's process rebuilds a verified policy from its bytes alone, and
    /// still does after the bundle's `expires` (a running sandbox keeps its policy).
    #[test]
    fn a_verified_policy_rebuilds_from_its_bytes_without_the_key() {
        let (kp, key) = key();
        let b = bundle(r#"[{"host":"api.example.com","port":443,"paths":["/v1/"],"adapter":{"type":"bearer","credential":"ex"}},{"host":"*","port":443}]"#);
        let p = verify(&kp, &key, &b).unwrap();
        assert_eq!(p.bytes(), b.as_bytes());
        let q = Policy::parse_trusted(p.bytes(), p.limits.max).unwrap();
        assert_eq!((&q.env, &q.subenv, q.version, q.expires, q.limits), (&p.env, &p.subenv, p.version, p.expires, p.limits));
        assert_eq!((&q.destinations, &q.resolvers, &q.templates, q.hash), (&p.destinations, &p.resolvers, &p.templates, p.hash));
        let (env, sub) = ids();
        let late = at(NOW + 7200);
        let sig = sign(&kp, b.as_bytes());
        assert_eq!(Policy::verify(b.as_bytes(), &sig, &key, &env, &sub, late, placeable()).unwrap_err().kind(), "expired");
        assert!(Policy::parse_trusted(b.as_bytes(), placeable()).is_ok(), "no expiry check");
        assert!(Policy::parse_trusted(b"{}", placeable()).is_err(), "still a well-formed bundle");
    }

    #[test]
    fn inconsistent_destinations_are_refused() {
        let (kp, key) = key();
        for bad in [
            r#"[{"host":"*","port":443,"adapter":{"type":"bearer","credential":"x"}}]"#,
            r#"[{"host":"*.example.com","port":443,"adapter":{"type":"basic","credential":"x"}}]"#,
            r#"[{"host":"a.example.com","port":443,"passthrough":true,"adapter":{"type":"basic","credential":"x"}}]"#,
            r#"[{"host":"a.example.com","port":443,"passthrough":true,"paths":["/v1/"]}]"#,
            r#"[{"host":"a.example.com","port":443,"paths":["v1/"]}]"#,
            r#"[{"host":"a.example.com","port":0}]"#,
            r#"[{"host":"203.0.113.9","port":443,"adapter":{"type":"bearer","credential":"x"}}]"#,
            r#"[{"host":"a.example.com","port":443,"adapter":{"type":"query","param":"a&b","credential":"x"}}]"#,
            r#"[{"host":"a.example.com","port":443,"adapter":{"type":"bearer","credential":"Not A Name"}}]"#,
            r#"[{"host":"a.example.com","port":443,"proxy":true}]"#,
        ] {
            assert!(verify(&kp, &key, &bundle(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_names_normalise() {
        assert_eq!("Api.Example.COM.".parse::<HostName>().unwrap().as_str(), "api.example.com");
        for bad in ["", ".", "a..b", "a b", &"a".repeat(64), "-é-"] {
            assert!(bad.parse::<HostName>().is_err(), "{bad:?}");
        }
        assert_eq!("192.0.2.1".parse::<Host>().unwrap(), Host::Ip(Ipv4Addr::new(192, 0, 2, 1)));
    }
}
