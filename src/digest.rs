// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::base64::Bytes;

/// The algorithm of a [`Digest`]
///
/// Interpreted according to the [IANA Named Information Hash Algorithm Registry]: an integer
/// is matched against the "ID" entries, e.g. `1`, and text against the "Hash Name String"
/// entries, e.g. `"sha-256"`. Using the integer form is RECOMMENDED. See
/// [draft-ietf-rats-eat-measured-component, Section 4.2].
///
/// [IANA Named Information Hash Algorithm Registry]: https://www.iana.org/assignments/named-information/named-information.xhtml
/// [draft-ietf-rats-eat-measured-component, Section 4.2]: https://www.ietf.org/archive/id/draft-ietf-rats-eat-measured-component-12.html#section-4.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DigestAlgorithm {
    Integer(i64),
    Text(String),
}

/// A digest as defined in [draft-ietf-rats-eat-measured-component, Section 4.2]
///
/// Encoded as a two-element array `[alg, val]`, with `val` as base64url text in JSON and as a
/// byte string in CBOR.
///
/// [draft-ietf-rats-eat-measured-component, Section 4.2]: https://www.ietf.org/archive/id/draft-ietf-rats-eat-measured-component-12.html#section-4.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub alg: DigestAlgorithm,
    pub val: Bytes,
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (&self.alg, &self.val).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (alg, val) = <(DigestAlgorithm, Bytes)>::deserialize(deserializer)?;
        Ok(Digest { alg, val })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ciborium::{de::from_reader, ser::into_writer};

    const SHA256: &str = "4c89eb4a5cec6b3f637cbeda6e0bc9daba28d8ff77268cecb77c77394fda7cd8";

    fn sha256() -> Bytes {
        Bytes(
            (0..SHA256.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&SHA256[i..i + 2], 16).unwrap())
                .collect(),
        )
    }

    #[test]
    fn json() {
        let text = r#"["sha-256","TInrSlzsaz9jfL7abgvJ2roo2P93Jozst3x3OU_afNg"]"#;
        let digest: Digest = serde_json::from_str(text).unwrap();
        assert_eq!(digest.alg, DigestAlgorithm::Text("sha-256".to_string()));
        assert_eq!(digest.val, sha256());
        assert_eq!(serde_json::to_string(&digest).unwrap(), text);
    }

    #[test]
    fn cbor() {
        let digest = Digest {
            alg: DigestAlgorithm::Integer(1),
            val: sha256(),
        };

        let mut buf = Vec::new();
        into_writer(&digest, &mut buf).unwrap();
        // [1, h'4c89...']
        assert_eq!(&buf[..4], &[0x82, 0x01, 0x58, 0x20]);
        assert_eq!(&buf[4..], digest.val.as_slice());
        assert_eq!(from_reader::<Digest, _>(buf.as_slice()).unwrap(), digest);
    }

    #[test]
    fn rejects_malformed() {
        for text in [
            r#"[]"#,
            r#"["sha-256"]"#,
            r#"["sha-256","TInr",1]"#,
            r#"[1.5,"TInr"]"#,
            r#"["sha-256","not base64!"]"#,
            r#"{"alg":"sha-256","val":"TInr"}"#,
        ] {
            assert!(serde_json::from_str::<Digest>(text).is_err(), "{text}");
        }
    }
}
