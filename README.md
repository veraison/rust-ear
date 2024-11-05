<!-- cargo-rdme start -->

An implementation of EAT Attestation Results token.

This crate provides an implementation of attestation results tokens that conforms to EAT
Attestation Results [draft-fv-rats-ear] specification. This defines a token intended to
communicate a set of appraisals of attested evidence produced by a verifier. Each appraisal is
based around a set of trust claims defined by Attestation Results for Secure Interactions
(AR4SI) [draft-ietf-rats-ar4si].

The attestation result may be serialized as a signed JSON or CBOR token (using JWT and COSE,
respectively).

[draft-fv-rats-ear]: https://datatracker.ietf.org/doc/draft-fv-rats-ear/
[draft-ietf-rats-ar4si]: https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/

# Examples

## Signing

```rust
use std::collections::BTreeMap;
use ear::{Ear, VerifierID, Algorithm, Appraisal, Extensions};

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
        extensions: Extensions::new(),
    };

    let signed = token.sign_jwt_pem(Algorithm::ES256, SIGNING_KEY.as_bytes()).unwrap();
}
```

## Verification

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

# Extensions and Profiles

EAR supports extension at top level (i.e. within the [`Ear`] struct), and also within
[`Appraisal`]s. An extension is an additional field definition. Extensions can be defined by
registering them with the `extensions` field of the corresponding struct. When registering an
extension, you must provide a string name (used in JSON), an integer key (used in CBOR), and an
[`ExtensionKind`] indicating which [`ExtensionValue`]s are valid.

## Registering individual extensions

Extensions can be registered directly with the corresponding struct's `extensions` field. Once
they have been registered, their values can be set and queried

```rust
use ear::{Ear, Appraisal, ExtensionKind, ExtensionValue};

let mut ear = Ear::new();
ear.extensions.register("ext.company-name", -65537, ExtensionKind::String).unwrap();

let mut appraisal = Appraisal::new();
// extensions for Ear's and Appraisal's have their own namespaces, so it is
// to use the same key in both.
appraisal.extensions.register("ext.timestamp", -65537, ExtensionKind::Integer).unwrap();

ear.extensions.set_by_name(
    "ext.company-name",
    ExtensionValue::String("Acme Inc.".to_string()),
).unwrap();

appraisal.extensions.set_by_key(
    -65537,
    ExtensionValue::Integer(1723534859),
).unwrap();

ear.submods.insert("road-runner-trap".to_string(), appraisal);

assert_eq!(
   ear.extensions.get_by_key(&-65537).unwrap(),
   ExtensionValue::String("Acme Inc.".to_string()),
);

assert_eq!(
   ear.submods["road-runner-trap"].extensions.get_by_name("ext.timestamp").unwrap(),
   ExtensionValue::Integer(1723534859),
);
```

Note: if you've obtained the [`Ear`] by deserializing from CBOR/JSON, [`Extensions`] struct
will cache any values for any unexpected fields, so that when you register extensions
afterwards, the corresponding unmarshaled values will be accessible.

## Using Profiles

Sets of extensions can be associated together within [`Profile`]s. A [`Profile`] can be
registered, and can then be retrieved by its `id` when creating a new [`Ear`] or [`Appraisal`]

```rust
use ear::{Ear, Appraisal, ExtensionKind, ExtensionValue, Profile, register_profile};

fn init_profile() {
    let mut profile = Profile::new("tag:github.com,2023:veraison/ear#acme-profile");

    profile.register_ear_extension(
        "ext.company-name", -65537, ExtensionKind::String).unwrap();
    profile.register_appraisal_extension(
        "ext.timestamp", -65537, ExtensionKind::Integer).unwrap();

    register_profile(&profile);
}

fn main() {
    init_profile();

    let mut ear = Ear::new_with_profile(
        "tag:github.com,2023:veraison/ear#acme-profile").unwrap();
    // these will apply to all submods/appraisals within a profiled EAR
    let mut appraisal = Appraisal::new_with_profile(
        "tag:github.com,2023:veraison/ear#acme-profile").unwrap();

    ear.extensions.set_by_name(
        "ext.company-name",
        ExtensionValue::String("Acme Inc.".to_string()),
    ).unwrap();

    appraisal.extensions.set_by_key(
        -65537,
        ExtensionValue::Integer(1723534859),
    ).unwrap();

    ear.submods.insert("road-runner-trap".to_string(), appraisal);

    assert_eq!(
       ear.extensions.get_by_key(&-65537).unwrap(),
       ExtensionValue::String("Acme Inc.".to_string()),
    );

    assert_eq!(
       ear.submods["road-runner-trap"]
            .extensions.get_by_name("ext.timestamp").unwrap(),
       ExtensionValue::Integer(1723534859),
    );
}

```

When deserializing an [`Ear`], its `profile` field will automatically be used to look up a
registred profile and add the associated extensions.

# JWT/CWT common claims

The only common JWT/CWT claim specified by EAR spec is "iat" (issued at). Other claims (e.g.
"iss" or "exp") are not expected to be present inside a valid EAR. It is, however, possible
to define them for a particular profile and include them as extensions via mechanisms described
above.

The following example shows how to include and then verify expiration time ("exp" JWT claim)
inside an EAR.

```rust
use ear::{Ear, Algorithm, Appraisal, ExtensionKind, ExtensionValue};
use std::time::{SystemTime, Duration, UNIX_EPOCH};

const VERIF_KEY: &str = r#"
{
    "kty":"EC",
    "crv":"P-256",
    "x":"G8fAud93NgCg8C_0bY1YqVZ5zNlkb-cNsGTQia7m0is",
    "y":"RK1gonvUKKQOCSHDwz3SiN9EijCqmXS4sDeRbc8RnL0"
}
"#;

const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPp4XZRnRHSMhGg0t
6yjQCRV35J4TUY4idLgiCu6EyLqhRANCAAQbx8C533c2AKDwL/RtjVipVnnM2WRv
5w2wZNCJrubSK0StYKJ71CikDgkhw8M90ojfRIowqpl0uLA3kW3PEZy9
-----END PRIVATE KEY-----
";

let mut ear = Ear::new();
ear.profile = "tag:github.com,2023:veraison/ear#acme-profile".to_string();
ear.vid.build = "vsts 0.0.1".to_string();
ear.vid.developer = "https://veraison-project.org".to_string();
ear.submods.insert("road-runner-trap".to_string(), Appraisal::new());
ear.extensions.register("exp", 4, ExtensionKind::Integer).unwrap();

// expire 10 days from now
let exp = SystemTime::now().checked_add(Duration::from_secs(60*60*24*10)).unwrap()
                        .duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

ear.extensions.set_by_name("exp", ExtensionValue::Integer(exp)).unwrap();


let signed = ear
    .sign_jwt_pem(Algorithm::ES256, SIGNING_KEY.as_bytes())
    .unwrap();

let mut ear2 =
    Ear::from_jwt_jwk(signed.as_str(), Algorithm::ES256, VERIF_KEY.as_bytes()).unwrap();

ear2.extensions.register("exp", 4, ExtensionKind::Integer).unwrap();

// Verify the token has not expired.
let exp2 = match ear2.extensions.get_by_name("exp").unwrap() {
    ExtensionValue::Integer(v) => Duration::from_secs(v as u64),
    _ => panic!(),
};
assert!(SystemTime::now().duration_since(UNIX_EPOCH).unwrap() < exp2);
```

# JWT headers

When signing with `sign_jwt_pem`/`sign_jwk_der`, only the `alg` header is set in the resulting
JWT based on the the specified algorithm. If other headers need to be specified, then
`sign_jwt_pem_with_header` and `sign_jwk_der_with_header` can be used instead; these take a
`jwt::Header` instead of an algorithm. A new header can be created from an algorithm using
`new_jwt_header`.

```rust
use std::collections::BTreeMap;
use ear::{Ear, VerifierID, Algorithm, Appraisal, Extensions, new_jwt_header};

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
        extensions: Extensions::new(),
    };

    let mut header = new_jwt_header(&Algorithm::ES256).unwrap();
    // set additional header(s)
    header.kid = Some("key-ident".to_string());

    let signed = token.sign_jwt_pem_with_header(&header, SIGNING_KEY.as_bytes()).unwrap();
}
```


# Limitations

- Signing supports PEM and DER keys; verification currently only supports JWK
  keys.
- JWT signing currently only supports ES256, ES384, EdDSA, PS256, PS384, and
  PS512.
- COSE signing currently only supports ES256, ES384, ES512, and EdDSA.

<!-- cargo-rdme end -->
