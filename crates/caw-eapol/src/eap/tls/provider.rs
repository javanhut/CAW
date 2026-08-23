//! Where the `rustls` crypto provider is chosen — and where caw declines to
//! choose one for you.
//!
//! # The problem
//!
//! `rustls` does no cryptography itself; it delegates to a `CryptoProvider`.
//! Three exist, and every one of them costs something caw has promised not to
//! spend:
//!
//! | Provider | Cost |
//! |---|---|
//! | `aws-lc-rs` | C and assembly, plus a `cmake` build dependency. Well maintained, FIPS-validatable, and the rustls default. |
//! | `ring` | C and assembly. Mature and widely deployed, but effectively in maintenance. |
//! | `rustls-rustcrypto` | Pure Rust, no C at all — and version `0.0.2-alpha`, unaudited, with no release since. |
//!
//! caw's whole premise is that the first two are what it exists to avoid, and
//! the third is code that would be guarding enterprise credentials against a
//! hostile network at an alpha maturity. That is a product decision with a
//! real security argument on both sides, and it is not one a library should
//! make silently on a user's behalf by picking a default.
//!
//! # What caw does instead
//!
//! Nothing, deliberately. `rustls` is built with its `custom-provider`
//! feature, so the `enterprise` build depends on *no* provider crate at all:
//! `cargo tree` shows neither `ring` nor `aws-lc-sys`, with or without the
//! feature. The provider arrives at runtime, from exactly one of two places:
//!
//!   * the embedding binary calls `CryptoProvider::install_default(..)` once
//!     at startup, or
//!   * the caller sets [`TlsConfig::crypto_provider`](super::TlsConfig::crypto_provider).
//!
//! If neither happened, [`resolve`] returns [`Error::NoCryptoProvider`] rather
//! than falling back to something. A missing provider is a build that was
//! never configured for Enterprise, and failing loudly at the first
//! authentication attempt is the only honest response.
//!
//! # If this is ever settled
//!
//! Compiling a provider in means adding it as an optional dependency and
//! returning it from [`resolve`]. This module is the entire blast radius:
//! nothing above the [`EapMethod`](crate::EapMethod) trait names a provider,
//! and nothing below it exists.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use crate::Error;

/// The provider this connection should use: the one the caller supplied, or
/// the process-wide default the embedding binary installed.
pub fn resolve(explicit: Option<Arc<CryptoProvider>>) -> Result<Arc<CryptoProvider>, Error> {
    if let Some(provider) = explicit {
        return Ok(provider);
    }
    CryptoProvider::get_default()
        .cloned()
        .ok_or(Error::NoCryptoProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default build has no provider installed, and that must surface as
    /// an error rather than as a connection that quietly uses something else.
    #[test]
    fn refuses_to_invent_a_provider() {
        assert!(matches!(resolve(None), Err(Error::NoCryptoProvider)));
    }
}
