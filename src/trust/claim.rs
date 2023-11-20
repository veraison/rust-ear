// SPDX-License-Identifier: Apache-2.0
use crate::error::Error;

use phf::{phf_map, Map};

use super::tier::TrustTier;

/// Description of a trustworthiness claim
#[derive(Debug, Clone)]
pub struct ClaimDescripiton<'a> {
    /// The key under which the claim is serialized in CBOR
    pub key: i8,
    /// The name under which the claim is serialized in JSON
    pub name: &'a str,
}

/// Description of the claim value
#[derive(Debug, Clone)]
pub struct ValueDescription<'a> {
    /// String tag given to the claim value
    pub tag: &'a str,
    /// A short description of the claim value
    ///
    /// This is intended to be used in error messages etc.
    pub short: &'a str,
    /// A longer description of the claim value
    ///
    /// This is a longer explanation of what the value is intended to represent.
    pub long: &'a str,
}

pub const VERIFIER_MALFUNCTION: i8 = -1;
pub const NO_CLAIM: i8 = 0;
pub const UNEXPECTED_EVIDENCE: i8 = 1;
pub const CRYPTO_VALIDATION_FAILED: i8 = 99;

// NOTE: a limitation of phf_map macro is that it cannot look up constant definitions, hence the
// use of literal in the keys below.

/// Values common to all claims.
pub static COMMON_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    -1i8 => ValueDescription{
        tag: "verifier_malfunction",
        short: "verifier malfunction",
        long:  "A verifier malfunction occurred during evidence appraisal."
    },
    0i8 => ValueDescription{
        tag: "no_claim",
        short: "no claim is being made",
        long:  "The evidence received is insufficient to make a conclusion."
    },
    1i8 => ValueDescription{
        tag: "unexpected_evidence",
        short: "unexpected evidence",
        long:  "The evidence received contains unexpected elements which the \
                verifier is unable to parse."
    },
    99i8 => ValueDescription{
        tag:   "crypto_failed",
        short: "cryptographic validation failed",
        long:  "Cryptographic validation of the Evidence has failed.",
    },
};

pub static INSTANCE_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 0,
    name: "instance-identity",
};

pub const TRUSTWORTHY_INSTANCE: i8 = 2;
pub const UNTRUSTWORTHY_INSTANCE: i8 = 96;
pub const UNRECOGNIZED_INSTANCE: i8 = 97;

pub static INSTANCE_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "recognized_instance",
        short: "trustworthy instance",
        long:  "The Attesting Environment is recognized, and the associated \
                instance of the Attester is not known to be compromised.",
    },
    96i8 => ValueDescription{
        tag:   "untrustworthy_instance",
        short: "recognized but not trustworthy",
        long:  "The Attesting Environment is recognized, but its unique private key \
                indicates a device which is not trustworthy.",
    },
    97i8 => ValueDescription{
        tag:   "unrecognized_instance",
        short: "not recognized",
        long:  "The Attesting Environment is not recognized; however the verifier \
                believes it should be.",
    },
};

pub static CONFIG_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 1,
    name: "configuration",
};

pub const APPROVED_CONFIG: i8 = 2;
pub const NO_CONFIG_VULNS: i8 = 3;
pub const UNSAFE_CONFIG: i8 = 32;
pub const UNAVAIL_CONFIG_ELEMS: i8 = 36;
pub const UNSUPPORTABLE_CONFIG: i8 = 96;

pub static CONFIG_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "approved_config",
        short: "all recognized and approved",
        long:  "The configuration is a known and approved config.",
    },
    3i8 => ValueDescription{
        tag:   "safe_config",
        short: "no known vulnerabilities",
        long:  "The configuration includes or exposes no known vulnerabilities",
    },
    32i8 => ValueDescription{
        tag:   "unsafe_config",
        short: "known vulnerabilities",
        long:  "The configuration includes or exposes known vulnerabilities.",
    },
    36i8 => ValueDescription{
        tag:   "unavailable_config",
        short: "config elements unavailable",
        long:  "Elements of the configuration relevant to security are unavailable \
                to the Verifier.",
    },
    96i8 => ValueDescription{
        tag:   "unsupportable_config",
        short: "unacceptable security vulnerabilities",
        long:  "The configuration is unsupportable as it exposes unacceptable \
                security vulnerabilities",
    },
};

pub static EXECUTABLES_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 2,
    name: "executables",
};

pub const APPROVED_RUNTIME: i8 = 2;
pub const APPROVED_BOOT: i8 = 3;
pub const UNSAFE_RUNTIME: i8 = 32;
pub const UNRECOGNIZED_RUNTIME: i8 = 33;
pub const CONTRAINDICATED_RUNTIME: i8 = 96;

pub static EXECUTABLES_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "approved_rt",
        short: "recognized and approved boot- and run-time",
        long:  "Only a recognized genuine set of approved executables, scripts, files, \
                and/or objects have been loaded during and after the boot process.",
    },
    3i8 => ValueDescription{
            tag:   "approved_boot",
            short: "recognized and approved boot-time",
            long:  "Only a recognized genuine set of approved executables have been \
                    loaded during the boot process.",
    },
    32i8 => ValueDescription{
        tag:   "unsafe_rt",
        short: "recognized but known bugs or vulnerabilities",
        long:  "Only a recognized genuine set of executables, scripts, files, and/or \
                objects have been loaded. However the Verifier cannot vouch for a subset \
                of these due to known bugs or other known vulnerabilities.",
    },
    33i8 => ValueDescription{
        tag:   "unrecognized_rt",
        short: "unrecognized run-time",
        long:  "Runtime memory includes executables, scripts, files, and/or objects which \
                are not recognized.",
    },
    96i8 => ValueDescription{
        tag:   "contraindicated_rt",
        short: "contraindicated run-time",
        long:  "Runtime memory includes executables, scripts, files, and/or object which \
                are contraindicated.",
    },
};

pub static FILE_SYSTEM_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 3,
    name: "file-system",
};

pub const APPROVED_FILES: i8 = 2;
pub const UNRECOGNIZED_FILES: i8 = 32;
pub const CONTRAINDICATED_FILES: i8 = 96;

pub static FILE_SYSTEM_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "approved_fs",
        short: "all recognized and approved",
        long:  "Only a recognized set of approved files are found.",
    },
    32i8 => ValueDescription{
        tag:   "unrecognized_fs",
        short: "unrecognized item(s) found",
        long:  "The file system includes unrecognized executables, scripts, or files.",
    },
    96i8 => ValueDescription{
        tag:   "contraindicated_fs",
        short: "contraindicated item(s) found",
        long:  "The file system includes contraindicated executables, scripts, or files.",
    },
};

pub static HARDWARE_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 4,
    name: "hardware",
};

pub const GENUINE_HARDWARE: i8 = 2;
pub const UNSAFE_HARDWARE: i8 = 32;
pub const CONTRAINDICATED_HARDWARE: i8 = 96;
pub const UNRECOGNIZED_HARDWARE: i8 = 97;

pub static HARDWARE_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "genuine_hw",
        short: "genuine",
        long:  "An Attester has passed its hardware and/or firmware verifications \
                needed to demonstrate that these are genuine/supported.",
    },
    32i8 => ValueDescription{
        tag:   "unsafe_hw",
        short: "genuine but known bugs or vulnerabilities",
        long:  "An Attester contains only genuine/supported hardware and/or firmware, \
                but there are known security vulnerabilities.",
    },
    96i8 => ValueDescription{
        tag:   "contraindicated_hw",
        short: "genuine but contraindicated",
        long:  "Attester hardware and/or firmware is recognized, but its trustworthiness \
                is contraindicated.",
    },
    97i8 => ValueDescription{
        tag:   "unrecognized_hw",
        short: "unrecognized",
        long:  "A Verifier does not recognize an Attester's hardware or firmware, but it \
                should be recognized.",
    },
};

pub static RUNTIME_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 5,
    name: "runtime-opaque",
};

pub const ENCRYPTED_MEMORY_RUNTIME: i8 = 2;
pub const ISOLATED_MEMORY_RUNTIME: i8 = 32;
pub const VISIBLE_MEMORY_RUNTIME: i8 = 96;

pub static RUNTIME_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "encrypted_rt",
        short: "memory encryption",
        long:  "the Attester's executing Target Environment and Attesting Environments \
                are encrypted and within Trusted Execution Environment(s) opaque to \
                the operating system, virtual machine manager, and peer applications.",
    },
    32i8 => ValueDescription{
        tag:   "isolated_rt",
        short: "memory isolation",
        long:  "the Attester's executing Target Environment and Attesting Environments \
                are inaccessible from any other parallel application or Guest VM running \
                on the Attester's physical device.",
    },
    96i8 => ValueDescription{
        tag:   "visible_rt",
        short: "visible",
        long:  "The Verifier has concluded that in memory objects are unacceptably visible \
                within the physical host that supports the Attester.",
    },
};

pub static STORAGE_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 6,
    name: "storage-opaque",
};

pub const HW_KEYS_ENCRYPTED_SECRETS: i8 = 2;
pub const SW_KEYS_ENCRYPTED_SECRETS: i8 = 32;
pub const UNENCRYPTED_SECRETS: i8 = 96;

pub static STORAGE_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "hw_encrypted_secrets",
        short: "encrypted secrets with HW-backed keys",
        long:  "the Attester encrypts all secrets in persistent storage via using keys \
                which are never visible outside an HSM or the Trusted Execution Environment \
                hardware.",
    },
    32i8 => ValueDescription{
        tag:   "sw_encrypted_secrets",
        short: "encrypted secrets with non HW-backed keys",
        long:  "the Attester encrypts all persistently stored secrets, but without using \
                hardware backed keys.",
    },
    96i8 => ValueDescription{
        tag:   "unencrypted_secrets",
        short: "unencrypted secrets",
        long:  "There are persistent secrets which are stored unencrypted in an Attester.",
    },
};

pub static SOURCED_DATA_CLAIM_DESC: &ClaimDescripiton<'static> = &ClaimDescripiton {
    key: 7,
    name: "sourced-data",
};

pub const TRUSTED_SOURCES: i8 = 2;
pub const UNTRUSTED_SOURCES: i8 = 32;
pub const CONTRAINDICATED_SOURCES: i8 = 96;

pub static SOURCED_DATA_CLAIM_MAP: &Map<i8, ValueDescription<'static>> = &phf_map! {
    2i8 => ValueDescription{
        tag:   "trusted_sources",
        short: "from attesters in the affirming tier",
        long:  "All essential Attester source data objects have been provided by other \
                Attester(s) whose most recent appraisal(s) had both no Trustworthiness \
                Claims of \"0\" where the current Trustworthiness Claim is \"Affirmed\", \
                as well as no \"Warning\" or \"Contraindicated\" Trustworthiness Claims.",
    },
    32i8 => ValueDescription{
        tag:   "untrusted_sources",
        short: "from unattested sources or attesters in the warning tier",
        long:  "Attester source data objects come from unattested sources, or attested \
                sources with \"Warning\" type Trustworthiness Claims",
    },
    96i8 => ValueDescription{
        tag:   "contraindicated_sources",
        short: "from attesters in the contraindicated tier",
        long:  "Attester source data objects come from contraindicated sources.",
    },
};

/// A trustworthiness claim
///
/// This is a claim regarding the trustworthiness of one aspect of the attested environment, as
/// defined in
/// <https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-04#name-trustworthiness-claims>
#[derive(Debug, Clone, Copy)]
pub struct TrustClaim {
    /// Claim value
    pub value: Option<i8>,
    desc: &'static ClaimDescripiton<'static>,
    value_desc: &'static Map<i8, ValueDescription<'static>>,
}

impl TrustClaim {
    /// Create a new claim based on the specified descriptions
    pub fn new(
        desc_map: &'static ClaimDescripiton<'static>,
        val_desc_map: &'static Map<i8, ValueDescription<'static>>,
    ) -> TrustClaim {
        TrustClaim {
            value: None,
            desc: desc_map,
            value_desc: val_desc_map,
        }
    }

    /// Return `true` if the value of this claim has been set, and `false` otherwise
    pub fn is_set(&self) -> bool {
        self.value.is_some()
    }

    /// Set the claim to the specified value
    pub fn set(&mut self, v: i8) {
        self.value = Some(v);
    }

    /// Return the claim's value
    ///
    /// If the value is unset, `0i8` is returned, indicating that no claim is being made.
    pub fn get(&self) -> i8 {
        self.value.unwrap_or(0i8)
    }

    /// Return the claim's value
    ///
    /// If the value is unset, `0i8` is returned, indicating that no claim is being made.
    pub fn value(&self) -> i8 {
        self.get()
    }

    /// Unset set the value of the claim
    pub fn unset(&mut self) {
        self.value = None
    }

    /// Get the string tag of the claim
    pub fn tag(&self) -> &str {
        self.desc.name
    }

    /// Get the integer key of the claim
    pub fn key(&self) -> i8 {
        self.desc.key
    }

    /// Get the string name of the claim's value
    ///
    /// If the value is one of those defined by [draft-ietf-rats-ar4si-04], its standard name is
    /// returned. Otherwise, the name is `"TrustClaim(i)"`, where `i` is the value.
    ///
    /// [draft-ietf-rats-ar4si-04]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-04
    pub fn value_name(&self) -> String {
        match self.value_desc() {
            Some(v) => v.tag.to_string(),
            None => format!("TrustClaim({})", self.value()),
        }
    }

    /// Get the short description of the claim's value
    ///
    /// If the value is one of those defined by [draft-ietf-rats-ar4si-04], its known description
    /// is returned. Otherwise, the description is an empty string.
    ///
    /// [draft-ietf-rats-ar4si-04]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-04
    pub fn value_short_desc(&self) -> String {
        match self.value_desc() {
            Some(v) => v.short.to_string(),
            None => "".to_string(),
        }
    }

    /// Get the long description of the claim's value
    ///
    /// If the value is one of those defined by [draft-ietf-rats-ar4si-04], its known description
    /// is returned. Otherwise, the description is an empty string.
    ///
    /// [draft-ietf-rats-ar4si-04]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-04
    pub fn value_long_desc(&self) -> String {
        match self.value_desc() {
            Some(v) => v.long.to_string(),
            None => "".to_string(),
        }
    }

    /// Return the trust tier of the claim's value
    ///
    /// If the value is unset, `TrustTier::None` is returned.
    pub fn tier(&self) -> TrustTier {
        let val = self.value();
        if (-1..=1).contains(&val) {
            TrustTier::None
        } else if (-32..32).contains(&val) {
            TrustTier::Affirming
        } else if (-96..96).contains(&val) {
            TrustTier::Warning
        } else {
            TrustTier::Contraindicated
        }
    }

    fn value_desc(&self) -> Option<&ValueDescription> {
        let val = self.value();
        if (-1..=1).contains(&val) || val == 99 {
            return COMMON_CLAIM_MAP.get(&val);
        }
        self.value_desc.get(&val)
    }
}

impl PartialEq<TrustClaim> for TrustClaim {
    fn eq(&self, other: &TrustClaim) -> bool {
        self.value() == other.value()
    }
}

impl PartialEq<&str> for TrustClaim {
    fn eq(&self, other: &&str) -> bool {
        self.value_name().as_str() == *other
    }
}

impl PartialEq<i8> for TrustClaim {
    fn eq(&self, other: &i8) -> bool {
        self.value() == *other
    }
}

impl TryFrom<&str> for TrustClaim {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "instance-identity" => Ok(TrustClaim::new(INSTANCE_CLAIM_DESC, INSTANCE_CLAIM_MAP)),
            "configuration" => Ok(TrustClaim::new(CONFIG_CLAIM_DESC, CONFIG_CLAIM_MAP)),
            "executables" => Ok(TrustClaim::new(
                EXECUTABLES_CLAIM_DESC,
                EXECUTABLES_CLAIM_MAP,
            )),
            "file-system" => Ok(TrustClaim::new(
                FILE_SYSTEM_CLAIM_DESC,
                FILE_SYSTEM_CLAIM_MAP,
            )),
            "hardware" => Ok(TrustClaim::new(HARDWARE_CLAIM_DESC, HARDWARE_CLAIM_MAP)),
            "runtime-opaque" => Ok(TrustClaim::new(RUNTIME_CLAIM_DESC, RUNTIME_CLAIM_MAP)),
            "storage-opaque" => Ok(TrustClaim::new(STORAGE_CLAIM_DESC, STORAGE_CLAIM_MAP)),
            "sourced-data" => Ok(TrustClaim::new(
                SOURCED_DATA_CLAIM_DESC,
                SOURCED_DATA_CLAIM_MAP,
            )),
            _ => Err(Error::InvalidName(value.to_string())),
        }
    }
}

impl TryFrom<i8> for TrustClaim {
    type Error = Error;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            0i8 => Ok(TrustClaim::new(INSTANCE_CLAIM_DESC, INSTANCE_CLAIM_MAP)),
            1i8 => Ok(TrustClaim::new(CONFIG_CLAIM_DESC, CONFIG_CLAIM_MAP)),
            2i8 => Ok(TrustClaim::new(
                EXECUTABLES_CLAIM_DESC,
                EXECUTABLES_CLAIM_MAP,
            )),
            3i8 => Ok(TrustClaim::new(
                FILE_SYSTEM_CLAIM_DESC,
                FILE_SYSTEM_CLAIM_MAP,
            )),
            4i8 => Ok(TrustClaim::new(HARDWARE_CLAIM_DESC, HARDWARE_CLAIM_MAP)),
            5i8 => Ok(TrustClaim::new(RUNTIME_CLAIM_DESC, RUNTIME_CLAIM_MAP)),
            6i8 => Ok(TrustClaim::new(STORAGE_CLAIM_DESC, STORAGE_CLAIM_MAP)),
            7i8 => Ok(TrustClaim::new(
                SOURCED_DATA_CLAIM_DESC,
                SOURCED_DATA_CLAIM_MAP,
            )),
            _ => Err(Error::InvalidValue(value)),
        }
    }
}

impl From<TrustClaim> for String {
    fn from(val: TrustClaim) -> String {
        val.tag().to_string()
    }
}

impl From<TrustClaim> for i8 {
    fn from(val: TrustClaim) -> i8 {
        val.key()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn equality() {
        let claim: TrustClaim = TrustClaim {
            value: Some(2i8),
            desc: INSTANCE_CLAIM_DESC,
            value_desc: INSTANCE_CLAIM_MAP,
        };
        assert_eq!(claim, claim.clone());
        assert_eq!(claim, TRUSTWORTHY_INSTANCE);
        assert_eq!(claim, 2i8);
        assert_eq!(claim, "recognized_instance");
    }

    #[test]
    fn tier() {
        let mut claim: TrustClaim = TrustClaim {
            value: None,
            desc: INSTANCE_CLAIM_DESC,
            value_desc: INSTANCE_CLAIM_MAP,
        };

        assert_eq!(claim.tier(), TrustTier::None);

        claim.set(1i8);
        assert_eq!(claim.tier(), TrustTier::None);

        claim.set(2i8);
        assert_eq!(claim.tier(), TrustTier::Affirming);

        claim.set(31i8);
        assert_eq!(claim.tier(), TrustTier::Affirming);

        claim.set(32i8);
        assert_eq!(claim.tier(), TrustTier::Warning);

        claim.set(95);
        assert_eq!(claim.tier(), TrustTier::Warning);

        claim.set(96);
        assert_eq!(claim.tier(), TrustTier::Contraindicated);

        claim.set(-1i8);
        assert_eq!(claim.tier(), TrustTier::None);

        claim.set(-2i8);
        assert_eq!(claim.tier(), TrustTier::Affirming);

        claim.set(-32i8);
        assert_eq!(claim.tier(), TrustTier::Affirming);

        claim.set(-33i8);
        assert_eq!(claim.tier(), TrustTier::Warning);

        claim.set(-96);
        assert_eq!(claim.tier(), TrustTier::Warning);

        claim.set(-97);
        assert_eq!(claim.tier(), TrustTier::Contraindicated);
    }
}
