//! Local key management for self-relay (phase 2, mechanism only).
//!
//! Minimal surface: generate random secp256k1 keys, load a key from an env
//! var, report the address, sign 32-byte hashes (deterministic RFC-6979 ECDSA
//! via `alloy`).
//!
//! # Hard secrecy rule
//!
//! Private key material must NEVER appear in logs, errors, or `Debug` output:
//!
//! - [`Keystore`] has **no derived `Debug`/`Clone`**. Its manual [`fmt::Debug`]
//!   impl prints only the public address.
//! - [`KeystoreError`] carries env-var *names*, never env-var *values*.
//! - No copies of the secret are kept outside the inner
//!   `alloy::signers::local::PrivateKeySigner`, whose k256 `SigningKey`
//!   implements `ZeroizeOnDrop`, so key bytes are wiped when the keystore drops.
//! - Never print/log/format a secret hex string or `to_bytes()` output.

use alloy::primitives::{Address, B256, U256};
use alloy::signers::local::{LocalSignerError, PrivateKeySigner};
use alloy::signers::SignerSync;
use std::fmt;

/// Errors from [`Keystore`] operations.
///
/// By construction no variant carries private key material: at most the
/// *name* of the env var is included, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// Env var is not set.
    EnvMissing {
        /// Name of the missing env var (not secret).
        var: String,
    },
    /// Env var is set but not valid unicode (value withheld).
    EnvNotUnicode {
        /// Name of the env var (not secret).
        var: String,
    },
    /// Env value is not 32-byte hex with optional `0x` prefix (value withheld).
    InvalidHex {
        /// Name of the env var (not secret).
        var: String,
    },
    /// Valid hex, but not a valid secp256k1 secret key
    /// (e.g. zero or `>=` curve order).
    InvalidSecretKey {
        /// Name of the env var (not secret).
        var: String,
    },
    /// Hash signing failed (not expected with a local key).
    SignFailed,
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvMissing { var } => write!(f, "env var not set: {var}"),
            Self::EnvNotUnicode { var } => {
                write!(f, "env var is not valid unicode: {var}")
            }
            Self::InvalidHex { var } => write!(
                f,
                "env var {var} is not valid 32-byte hex (expected 64 hex chars, optional 0x prefix)"
            ),
            Self::InvalidSecretKey { var } => write!(
                f,
                "env var {var} is valid hex but not a valid secp256k1 secret key"
            ),
            Self::SignFailed => write!(f, "failed to sign hash"),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Local secp256k1 keystore wrapping an alloy [`PrivateKeySigner`].
///
/// Deliberately not `Clone` (cloning would duplicate key material) and with a
/// manual [`fmt::Debug`] impl that exposes only the public address.
pub struct Keystore {
    signer: PrivateKeySigner,
}

impl fmt::Debug for Keystore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public address only. Never the secret.
        f.debug_struct("Keystore")
            .field("address", &self.signer.address())
            .finish()
    }
}

impl Keystore {
    /// Generates a new random secp256k1 key.
    pub fn generate() -> Self {
        Self {
            signer: PrivateKeySigner::random(),
        }
    }

    /// Loads a key from the env var `var`.
    ///
    /// The value must be 32-byte hex with an optional `0x`/`0X` prefix;
    /// surrounding whitespace is trimmed. Returns an error (never panics) on
    /// missing/non-unicode/malformed values. Error messages contain the var
    /// name only, never the value.
    pub fn from_env(var: &str) -> Result<Self, KeystoreError> {
        let raw = std::env::var(var).map_err(|e| match e {
            std::env::VarError::NotPresent => KeystoreError::EnvMissing {
                var: var.to_owned(),
            },
            // `NotUnicode` payload would contain the secret value: withhold it.
            std::env::VarError::NotUnicode(_) => KeystoreError::EnvNotUnicode {
                var: var.to_owned(),
            },
        })?;
        let trimmed = raw.trim();
        let hex = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let signer: PrivateKeySigner = hex.parse().map_err(|e| match e {
            LocalSignerError::HexError(_) => KeystoreError::InvalidHex {
                var: var.to_owned(),
            },
            _ => KeystoreError::InvalidSecretKey {
                var: var.to_owned(),
            },
        })?;
        Ok(Self { signer })
    }

    /// Returns the Ethereum address of this key.
    pub fn address(&self) -> Address {
        self.signer.address()
    }
}

/// Signs a 32-byte hash with `key` (deterministic RFC-6979 ECDSA via alloy
/// [`SignerSync::sign_hash_sync`]; the hash is signed exactly as supplied, no
/// prefixing or domain separation).
///
/// Returns `(r, s, v)` where `v` is the y-parity byte (`0` or `1`;
/// Electrum notation is `27 + v`).
pub fn sign_hash(key: &Keystore, hash: &[u8; 32]) -> Result<(U256, U256, u8), KeystoreError> {
    let sig = key
        .signer
        .sign_hash_sync(&B256::from(*hash))
        .map_err(|_| KeystoreError::SignFailed)?;
    Ok((sig.r(), sig.s(), u8::from(sig.v())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Foundry/Hardhat dev key #0 (public test vector) and its address.
    /// NOTE: the task brief quoted this key truncated (`...784d7b4ee3`, 60 hex
    /// chars — invalid length); the full 32-byte key below is the canonical
    /// public dev vector matching the expected address.
    const DEV_KEY_HEX: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const DEV_KEY_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn generate_gives_distinct_addresses() {
        let a = Keystore::generate();
        let b = Keystore::generate();
        assert_ne!(a.address(), b.address());
        assert_ne!(a.address(), Address::ZERO);
        assert_ne!(b.address(), Address::ZERO);
    }

    #[test]
    fn from_env_known_vector() {
        let expected: Address = DEV_KEY_ADDR.parse().unwrap();

        std::env::set_var("SIGNER_TEST_KNOWN_VECTOR_PLAIN", DEV_KEY_HEX);
        let ks = Keystore::from_env("SIGNER_TEST_KNOWN_VECTOR_PLAIN").unwrap();
        assert_eq!(ks.address(), expected);

        // `0x` prefix must be trimmed too.
        std::env::set_var(
            "SIGNER_TEST_KNOWN_VECTOR_0X",
            format!("0x{DEV_KEY_HEX}"),
        );
        let ks = Keystore::from_env("SIGNER_TEST_KNOWN_VECTOR_0X").unwrap();
        assert_eq!(ks.address(), expected);

        // Surrounding whitespace must be trimmed too.
        std::env::set_var(
            "SIGNER_TEST_KNOWN_VECTOR_WS",
            format!("  0X{DEV_KEY_HEX}\n"),
        );
        let ks = Keystore::from_env("SIGNER_TEST_KNOWN_VECTOR_WS").unwrap();
        assert_eq!(ks.address(), expected);
    }

    #[test]
    fn sign_hash_is_deterministic() {
        std::env::set_var("SIGNER_TEST_DETERMINISM", DEV_KEY_HEX);
        let ks = Keystore::from_env("SIGNER_TEST_DETERMINISM").unwrap();
        let hash = [0x42u8; 32];

        let first = sign_hash(&ks, &hash).unwrap();
        let second = sign_hash(&ks, &hash).unwrap();
        assert_eq!(first, second);

        let (r, s, v) = first;
        assert_ne!(r, U256::ZERO);
        assert_ne!(s, U256::ZERO);
        assert!(v <= 1, "v must be y-parity (0 or 1), got {v}");

        // A different hash must (overwhelmingly likely) give a different signature.
        let other = sign_hash(&ks, &[0x43u8; 32]).unwrap();
        assert_ne!(first, other);
    }

    #[test]
    fn invalid_hex_is_error_not_panic() {
        // Garbage.
        std::env::set_var("SIGNER_TEST_BAD_GARBAGE", "not-hex!!");
        let err = Keystore::from_env("SIGNER_TEST_BAD_GARBAGE").unwrap_err();
        assert_eq!(
            err,
            KeystoreError::InvalidHex {
                var: "SIGNER_TEST_BAD_GARBAGE".to_owned()
            }
        );

        // Right charset, wrong length.
        std::env::set_var("SIGNER_TEST_BAD_SHORT", "0x1234");
        assert!(Keystore::from_env("SIGNER_TEST_BAD_SHORT").is_err());

        // Empty / whitespace-only.
        std::env::set_var("SIGNER_TEST_BAD_EMPTY", "   ");
        assert!(Keystore::from_env("SIGNER_TEST_BAD_EMPTY").is_err());

        // Missing var.
        std::env::remove_var("SIGNER_TEST_DEFINITELY_UNSET_VAR");
        let err = Keystore::from_env("SIGNER_TEST_DEFINITELY_UNSET_VAR").unwrap_err();
        assert_eq!(
            err,
            KeystoreError::EnvMissing {
                var: "SIGNER_TEST_DEFINITELY_UNSET_VAR".to_owned()
            }
        );

        // Valid hex but not a valid secret key (zero).
        std::env::set_var("SIGNER_TEST_BAD_ZERO", "0x0000000000000000000000000000000000000000000000000000000000000000");
        let err = Keystore::from_env("SIGNER_TEST_BAD_ZERO").unwrap_err();
        assert_eq!(
            err,
            KeystoreError::InvalidSecretKey {
                var: "SIGNER_TEST_BAD_ZERO".to_owned()
            }
        );
    }

    #[test]
    fn errors_and_debug_never_leak_secret() {
        std::env::set_var("SIGNER_TEST_NO_LEAK", DEV_KEY_HEX);
        let ks = Keystore::from_env("SIGNER_TEST_NO_LEAK").unwrap();

        // Keystore Debug shows the address but never the secret hex.
        let dbg = format!("{ks:?}");
        assert!(!dbg.contains(DEV_KEY_HEX));
        assert!(dbg.contains("Keystore"));

        // Error Display/Debug for a bad value never echoes the value.
        std::env::set_var("SIGNER_TEST_NO_LEAK_BAD", "deadbeefZZZ");
        let err = Keystore::from_env("SIGNER_TEST_NO_LEAK_BAD").unwrap_err();
        for rendered in [format!("{err}"), format!("{err:?}")] {
            assert!(!rendered.contains("deadbeefZZZ"), "{rendered}");
        }
        // Var name (non-secret) is fine to include.
        assert!(format!("{err}").contains("SIGNER_TEST_NO_LEAK_BAD"));
    }
}
