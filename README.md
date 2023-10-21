# jsl: JOSE Simple Licensing

Crate implementing the verification for the licensing scheme explained [here](https://www.linkedin.com/pulse/simple-licensing-validation-scheme-using-jose-santiago-alessandri-4n23c).

It provides a `LicenseVerifier` struct that allows for verifying a JSON object in the appropriate
format with the key it is initialized.

## Example

```rust
use jls::License;
use jls::verification::LicenseVerifier;

use serde_json;

fn main() {
    // Public Key in JWK format. Should be embedded in the binary
    let public_key: serde_json::Value = serde_json::json!({
        "alg": "RS512",
        "kty": "RSA",
        "n": "ziWUk8mSfgyLjHt_9iqY3PrwkmbrGkfYKckFuYAtbaBG4RLdluDOJu0xyIhR9l4jOCWqlt_C1ks2ED8lY9kXB\
        gIg5LQI6d1XhPOdoF-GlKFfpQGtWQ_l6Pkg3nMQSGZoW76ISuVhXebMk4x73y928-i_xCGzTUSpJYEAHQRF_hM_C5w2-\
        Zm8u7cm5GlOxKlpVAmRP6mkWGRAR3C476MMn7gP4_PlzgA522O3QMqVXuL5tyL7zsDNkDwtrzz2WBgqmKPJKp3XhuJsb\
        m2ytR9QHvHZ0FcxuUxx4xWMaFadSQc7fMShTCY_YNzHA5P_SMXIp5jwf-sqCUGFRssFw_3ZaZmSC0W70Er39Qb_PPXfr\
        LL35N0uuxp0uIyuTWz-8Swbyu6jWWzwaeNi0aZuzGr3_uItjC1Dk8vSQTjsFA-S-Ww5RfXC7Jigqq03I9jwp2h5EONJf\
        9QB8rmnYndtNepZ4DlFoC1_6kP2Z_TsYQCCyPRIa5ame0Sj_27VSLWJybJZgHc3Ky9msaSdT9y0qCX9oG-Vgt_CmMmMr\
        ED7s6LFEWyED6uBUFZJWCKPCwOA9PAjv7xovufykwUe3SyWfPTNYkPPSv6aY4riVFnvev4P3SWEY1OLkNh5LqOC97yR7\
        m9FOkZFIbkgfI9tGBVcBfiGIkKI4_lYUVELslLxfAj7pz0",
        "e": "AQAB"
    });

    // This should be retrieved from a file or something similar 
    let verifiable_license = serde_json::json!({
        "license": {
            "id": "0b5b88f5-a264-4f90-8406-50b01d9515c8",
            "expirationDate": "2024-10-01T00:00:00Z",
            "customData": {
                "owner": "John Doe"
            }
        },
        "licenseValidation": {
            "payload": "eyJpZCI6IjBiNWI4OGY1LWEyNjQtNGY5MC04NDA2LTUwYjAxZDk1MTVjOCIsImV4cGlyYXRpb25E\
                YXRlIjoiMjAyNC0xMC0wMVQwMDowMDowMFoiLCJjdXN0b21EYXRhIjp7Im93bmVyIjoiSm9obiBEb2UifX0",
            "protected": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9",
            "signature": "EZh1khxXXnB8bKNS5PZAOReIZ7OF0hoII5Xp-cpj6L5vwtLUOKRQAgiYymnZZDveYtzVrFyW4H\
                oFtmZDQgoCy0n8G1grhhg0WCd9-WZ2iEIo8xEEPAUHqyD2r_UHFnJejbJZLoNfe4IFEtU_xSJ8dpVQqCxPHE\
                Mmngtio6Aedqh9JF7pNbjlBYmWewj59otEGvbvQR_-odKO78HM-oEVpaix3h3RPAfIpiKhijrUDBQ208PKi_\
                NV3I3ALagu2k6HT38WzUwiy793j9CfTQhUQfsC3YyoED_Ku-buGKzo8i5DUxhSgAAmU79GXQFraD-qV_dIz4\
                oGYPDIga2QUk-tpaAfVvu04LxZB-GtyH8_9vf7dXaxDULM5Jsm68aaCKhc1V7_cHKKkHkvP5YLZauX0ZajUa\
                cIbn2s9n36e_FB2ty4yx9aA7Na2HzDYYf10WsLahuseU5LxDQv1KysoccOZdA4ifTTtshld_hlNMxAizvgcw\
                sEkjfAJP_QnHhjQ0r912JYqItczTmr3tbiYWR7Xw_y02Hz4JVqEs4qTO4oFIqhLREdoldf_MP7dFBoiPUJmN\
                5r1zyQ6MGwdYTHNzX5zR9YUg2tDXskQeyOGoPqaCdWHr8Kofd4PboLX48sYf18mdGGwMotdDKTytZCyTTswN\
                YFlaTtKNZYz5UZ6J-blx4"
        }
    });

    let verifier = LicenseVerifier::new(public_key).expect("Failed to initialize LicenseVerifier");
    let Ok(license) = verifier.verify(verifiable_license) else {
        // Failed to successfully verify the license
    };
}
```