//! The nonce service: single-use nonces with a TTL, per environment.
//!
//! Nonces live in this process's memory, so the verifier runs as one instance
//! (DECISIONS.md); a shared store is needed before it scales out.

use std::collections::HashMap;
use std::sync::Mutex;

use common::evidence::Nonce;
use common::ids::EnvId;

/// Why a nonce was refused (check 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceFailure {
    /// This verifier never issued it.
    Unknown,
    /// Issued for another environment.
    WrongEnv,
    /// Older than the TTL.
    Expired { issued_at: u64, now: u64 },
    /// Already used by an unlock.
    Used,
}

#[derive(Debug)]
struct Issued {
    env: EnvId,
    at: u64,
    used: bool,
}

#[derive(Debug, Default)]
pub struct Nonces {
    issued: Mutex<HashMap<Nonce, Issued>>,
}

impl Nonces {
    /// Issues a fresh nonce for `env`, and forgets nonces older than `2 * ttl`.
    pub fn issue(&self, env: &EnvId, now: u64, ttl: u64) -> Nonce {
        let mut bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut bytes).expect("the system RNG does not fail");
        let nonce = Nonce(bytes);
        let mut issued = self.lock();
        issued.retain(|_, i| now.saturating_sub(i.at) <= ttl.saturating_mul(2));
        issued.insert(nonce, Issued {
            env: env.clone(),
            at: now,
            used: false,
        });
        nonce
    }

    /// Records a nonce as issued at `at`, for replaying recorded evidence (the corpus).
    pub fn record(&self, nonce: Nonce, env: &EnvId, at: u64) {
        self.lock().insert(nonce, Issued {
            env: env.clone(),
            at,
            used: false,
        });
    }

    /// Marks `nonce` used. Fails if it was not issued for `env`, has expired or was
    /// used before; a nonce presented once is spent whatever the outcome.
    pub fn consume(&self, nonce: &Nonce, env: &EnvId, now: u64, ttl: u64) -> Result<(), NonceFailure> {
        let mut issued = self.lock();
        let entry = issued.get_mut(nonce).ok_or(NonceFailure::Unknown)?;
        let was_used = std::mem::replace(&mut entry.used, true);
        if &entry.env != env {
            return Err(NonceFailure::WrongEnv);
        }
        if was_used {
            return Err(NonceFailure::Used);
        }
        if now.saturating_sub(entry.at) > ttl {
            return Err(NonceFailure::Expired {
                issued_at: entry.at,
                now,
            });
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Nonce, Issued>> {
        // A panic while holding the lock leaves the map consistent (every mutation is
        // a single insert or field write), so a poisoned lock is still usable.
        self.issued.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(s: &str) -> EnvId {
        s.parse().unwrap()
    }

    #[test]
    fn single_use_within_ttl() {
        let n = Nonces::default();
        let nonce = n.issue(&env("a"), 100, 300);
        assert_eq!(n.consume(&nonce, &env("a"), 150, 300), Ok(()));
        assert_eq!(n.consume(&nonce, &env("a"), 151, 300), Err(NonceFailure::Used));
    }

    #[test]
    fn unknown_expired_and_foreign() {
        let n = Nonces::default();
        assert_eq!(n.consume(&Nonce([1; 32]), &env("a"), 0, 300), Err(NonceFailure::Unknown));
        let old = n.issue(&env("a"), 100, 300);
        assert_eq!(
            n.consume(&old, &env("a"), 401, 300),
            Err(NonceFailure::Expired { issued_at: 100, now: 401 })
        );
        let other = n.issue(&env("b"), 100, 300);
        assert_eq!(n.consume(&other, &env("a"), 100, 300), Err(NonceFailure::WrongEnv));
        assert_ne!(n.issue(&env("a"), 0, 300), n.issue(&env("a"), 0, 300));
    }
}
