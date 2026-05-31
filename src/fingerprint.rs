/// Phase 1 + 2 — Hardware fingerprint + K-of-N threshold + Argon2id KDF

use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

pub const TOTAL_SOURCES: usize = 9;
pub const THRESHOLD: usize = 7; // require 7 of 9

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    pub cpuid:          Option<String>, // CPU family/model/stepping/brand
    pub smbios_uuid:    Option<String>, // Motherboard system UUID
    pub nic_mac:        Option<String>, // First physical NIC MAC
    pub ssd_serial:     Option<String>, // Primary drive serial
    pub tpm_ek:         Option<String>, // TPM version/vendor identity
    pub gpu_device_id:  Option<String>, // GPU vendor:device:subsystem
    pub dimm_spd:       Option<String>, // RAM manufacturer + part + serial
    pub cache_topology: Option<String>, // L1/L2/L3 size + associativity
    pub pcie_topology:  Option<String>, // Sorted PCI device tree
}

impl HardwareFingerprint {
    pub fn present_sources(&self) -> Vec<(&'static str, &str)> {
        let mut s = Vec::new();
        macro_rules! push {
            ($label:expr, $field:expr) => {
                if let Some(ref v) = $field {
                    s.push(($label, v.as_str()));
                }
            };
        }
        push!("cpuid",          self.cpuid);
        push!("smbios_uuid",    self.smbios_uuid);
        push!("nic_mac",        self.nic_mac);
        push!("ssd_serial",     self.ssd_serial);
        push!("tpm_ek",         self.tpm_ek);
        push!("gpu_device_id",  self.gpu_device_id);
        push!("dimm_spd",       self.dimm_spd);
        push!("cache_topology", self.cache_topology);
        push!("pcie_topology",  self.pcie_topology);
        s
    }
}

/// Wraps the 256-bit derived key; zeroed on drop.
pub struct DerivedKey(pub [u8; 32]);

impl Drop for DerivedKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Debug)]
pub enum FingerprintError {
    BelowThreshold { found: usize, required: usize },
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FingerprintError::BelowThreshold { found, required } =>
                write!(f, "Hardware mismatch: {found}/{required} sources — wrong machine"),
        }
    }
}

/// Derive the 256-bit PERMANENT_MASTER_KEY.
///
/// Each present identifier is hashed independently with SHA3-512 (label:value).
/// Hashes are sorted (order-independent), concatenated, then fed into Argon2id.
///
/// `salt`  — 16 random bytes stored in the ciphertext header (not secret).
/// `epoch` — optional rotation tag; pass "" to disable.
pub fn derive_master_key(
    fp: &HardwareFingerprint,
    salt: &[u8; 16],
    passphrase: &str,
) -> Result<DerivedKey, FingerprintError> {
    let sources = fp.present_sources();

    if sources.len() < THRESHOLD {
        return Err(FingerprintError::BelowThreshold {
            found: sources.len(),
            required: THRESHOLD,
        });
    }

    // Hash each source independently — missing sources contribute nothing.
    let mut hashes: Vec<[u8; 64]> = sources.iter().map(|(label, value)| {
        let mut h = Sha3_512::new();
        h.update(label.as_bytes());
        h.update(b":");
        h.update(value.as_bytes());
        h.finalize().into()
    }).collect();

    hashes.sort_unstable(); // order-independent

    let mut pool: Vec<u8> = hashes.iter().flatten().copied().collect();

    if !passphrase.is_empty() {
        pool.extend_from_slice(passphrase.as_bytes());
    }

    // Argon2id: 512 MB memory-hard, 4 passes, single-threaded for determinism.
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(512 * 1024, 4, 1, Some(32))
        .expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(&pool, salt, &mut key_bytes)
        .expect("argon2 derivation failed");

    pool.zeroize();
    Ok(DerivedKey(key_bytes))
}
