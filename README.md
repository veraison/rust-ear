This is an implementation of [EAT Attestation
Results](https://datatracker.ietf.org/doc/draft-fv-rats-ear/) and [Attestation Results for Secure Interactions (AR4SI)](https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/).

## Examples

### Signing

```rust
use std::collections::BTreeMap;
use ear::{Ear, VerifierID, Algorithm, Appraisal};

const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPp4XZRnRHSMhGg0t
6yjQCRV35J4TUY4idLgiCu6EyLqhRANCAAQbx8C533c2AKDwL/RtjVipVnnM2WRv
5w2wZNCJrubSK0StYKJ71CikDgkhw8M90ojfRIowqpl0uLA3kW3PEZy9
-----END PRIVATE KEY-----
";

fn main() {
    let token = Ear{
        profile: "test".to_string(),
        iat: 1,
        vid: VerifierID {
            build: "vsts 0.0.1".to_string(),
            developer: "https://veraison-project.org".to_string(),
        },
        raw_evidence: None,
        nonce: None,
        submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
    };

    let signed = token.sign_jwt_pem(Algorithm::ES256, SIGNING_KEY.as_bytes()).unwrap();
}
```

### Verification

```rust
use ear::{Ear, Algorithm};

const VERIF_KEY: &str = r#"
{
    "kty":"EC",
    "crv":"P-256",
    "x":"G8fAud93NgCg8C_0bY1YqVZ5zNlkb-cNsGTQia7m0is",
    "y":"RK1gonvUKKQOCSHDwz3SiN9EijCqmXS4sDeRbc8RnL0"
}
"#;

fn main() {
    let signed = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJlYXRfcHJvZmlsZSI6InRlc3QiLCJpYXQiOjEsImVhci52ZXJpZmllci1pZCI6eyJkZXZlbG9wZXIiOiJodHRwczovL3ZlcmFpc29uLXByb2plY3Qub3JnIiwiYnVpbGQiOiJ2c3RzIDAuMC4xIn0sInN1Ym1vZHMiOnsidGVzdCI6eyJlYXIuc3RhdHVzIjoibm9uZSJ9fX0.G25v0j0NDQhSOcK3Jtfq5vqVxnoWuWf-Q0DCNkCwpyB03DGr25ZDJ3IDSAHVPZrr6TVMwj8RcGEzQnCrucem4Q";

    let token = Ear::from_jwt_jwk(signed, Algorithm::ES256, VERIF_KEY.as_bytes()).unwrap();
    println!("EAR profiles: {}", token.profile);
}
```

## Limitations

- Signing supports PEM and DER keys; verification currently only supports JWK
  keys.
- JWT signing currently only supports ES256, ES384, EdDSA, PS256, PS384, and
  PS512.
- COSE signing currently only supports ES256, ES384, ES512, and EdDSA.
