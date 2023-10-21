use crate::{License, VerifiableLicense};
use jose_jwk::crypto::KeyInfo;
use jose_jwk::jose_jwa::{Algorithm, Signing};
use jose_jwk::{Jwk, Key};
use jose_jws::Jws;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha512;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseVerificationError {
    InvalidVerifiableLicense,
    TamperedLicense,
    VerificationFailure,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseVerifierError {
    KeyIsNotJwk,
    KeyTypeNotSupported,
}

pub struct LicenseVerifier {
    rsa_public_key: RsaPublicKey,
}

impl LicenseVerifier {
    pub fn new(public_key: serde_json::Value) -> Result<Self, LicenseVerifierError> {
        let parsed_public_key: Jwk =
            serde_json::from_value(public_key).map_err(|_| LicenseVerifierError::KeyIsNotJwk)?;

        if !parsed_public_key.is_supported(&Algorithm::from(Signing::Rs512)) {
            return Err(LicenseVerifierError::KeyTypeNotSupported);
        }

        let rsa_key;
        if let Key::Rsa(jwk_rsa_key) = parsed_public_key.key {
            rsa_key = RsaPublicKey::try_from(&jwk_rsa_key)
                .map_err(|_| LicenseVerifierError::KeyTypeNotSupported)?;
        } else {
            return Err(LicenseVerifierError::KeyTypeNotSupported);
        }

        return Ok(Self {
            rsa_public_key: rsa_key,
        });
    }

    pub fn verify(
        &self,
        verifiable_license_json: serde_json::Value,
    ) -> Result<License, LicenseVerificationError> {
        let verifiable_license: VerifiableLicense = serde_json::from_value(verifiable_license_json)
            .map_err(|_| LicenseVerificationError::InvalidVerifiableLicense)?;

        let license_validation_obj = verifiable_license
            .license_validation
            .as_object()
            .ok_or(LicenseVerificationError::InvalidVerifiableLicense)?;
        let protected_to_verify = license_validation_obj
            .get("protected")
            .and_then(|v| v.as_str())
            .ok_or(LicenseVerificationError::InvalidVerifiableLicense)?;
        let payload_to_verify = license_validation_obj
            .get("payload")
            .and_then(|v| v.as_str())
            .ok_or(LicenseVerificationError::InvalidVerifiableLicense)?;
        let data_to_verify = format!("{}.{}", protected_to_verify, payload_to_verify);

        let Jws::Flattened(license_validation) =
            serde_json::from_value(verifiable_license.license_validation.clone())
                .map_err(|_| LicenseVerificationError::InvalidVerifiableLicense)?
        else {
            return Err(LicenseVerificationError::InvalidVerifiableLicense);
        };

        let payload_slice = license_validation
            .payload
            .as_deref()
            .ok_or(LicenseVerificationError::InvalidVerifiableLicense)?;
        let protected_license: License = serde_json::from_slice(payload_slice)
            .map_err(|_| LicenseVerificationError::InvalidVerifiableLicense)?;

        if protected_license != verifiable_license.license {
            return Err(LicenseVerificationError::TamperedLicense);
        }

        let rsa_signature =
            Signature::try_from(license_validation.signature.signature.iter().as_ref())
                .map_err(|_| LicenseVerificationError::InvalidVerifiableLicense)?;
        let verifying_key = VerifyingKey::<Sha512>::new(self.rsa_public_key.clone());
        verifying_key
            .verify(data_to_verify.as_bytes(), &rsa_signature)
            .map_err(|_| LicenseVerificationError::VerificationFailure)?;

        Ok(protected_license)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lazy_static::lazy_static;

    lazy_static! {
        static ref PUBLIC_KEY_JWK_JSON: serde_json::Value = serde_json::json!({
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
        static ref EXPECTED_LICENSE: serde_json::Value = serde_json::json!({
            "id": "0b5b88f5-a264-4f90-8406-50b01d9515c8",
            "expirationDate": "2024-10-01T00:00:00Z",
            "customData": {
                "owner": "John Doe"
            }
        });
        static ref VALID_VERIFIABLE_LICENSE: serde_json::Value = serde_json::json!({
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
    }

    #[test]
    fn verifier_initializer_works() {
        let verifier =
            LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone()).expect("Initialization should work");

        let verified_license = verifier
            .verify(VALID_VERIFIABLE_LICENSE.clone())
            .expect("Verification should succeed");

        let expected_license: License = serde_json::from_value(EXPECTED_LICENSE.clone()).unwrap();

        assert_eq!(verified_license, expected_license);
    }

    #[test]
    fn verifier_with_non_jwk_key() {
        let non_jwk_key = serde_json::json!({
            "random": "ABC",
            "someOtherField": 123456,
        });

        let result = LicenseVerifier::new(non_jwk_key);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerifierError::KeyIsNotJwk);
    }

    #[test]
    fn verifier_with_non_rsa_key() {
        let non_rsa_key = serde_json::json!({
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "6G267OCXrqG-Kr5RuHmUOO7OoRMItapzzG3z0I4pnEU",
            "y": "i3vOYB9DU-pbCS_vD0ob9X6jvWX2W-TZxF-tJ4sc710"
        });

        let result = LicenseVerifier::new(non_rsa_key);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerifierError::KeyTypeNotSupported);
    }

    #[test]
    fn verifier_with_small_rsa_key() {
        let small_rsa_key = serde_json::json!({
            "alg": "RS512",
            "kty": "RSA",
            "n": "xDfeAfrErnWVBQHeiD4VuZRLy6QXhTJG7LMkC9JZD33T-rTlKmXpY8uPHXxq04K5hVWBupn27FCbUiVaOJ\
                kmWoWfbiiIZC9vBgaF1d7p24te5JBTX-nHhTeySHH6AMx2Q78MDwkDQ7gv8PgfBp4j_66h3mVLRNvol-c13E\
                PGz4M",
            "e": "AQAB"
        });

        let result = LicenseVerifier::new(small_rsa_key);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerifierError::KeyTypeNotSupported);
    }

    #[test]
    fn license_verification_with_invalid_input() {
        let invalid_input = serde_json::json!({
            "random": "ABC",
            "someOtherField": 123456,
        });

        let verifier = LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone())
            .expect("Verifier instantiation must work");

        let result = verifier.verify(invalid_input);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerificationError::InvalidVerifiableLicense);
    }

    #[test]
    fn license_verification_with_non_jws_validation() {
        let invalid_input = serde_json::json!({
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
                "signatura": "EZh1khxXXnB8bKNS5PZAOReIZ7OF0hoII5Xp-cpj6L5vwtLUOKRQAgiYymnZZDveYtzVrFyW4H\
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

        let verifier = LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone())
            .expect("Verifier instantiation must work");

        let result = verifier.verify(invalid_input);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerificationError::InvalidVerifiableLicense);
    }

    #[test]
    fn license_verification_with_tampered_license() {
        let tampered_license = serde_json::json!({
            "license": {
                "id": "0b5b88f5-a264-4f90-8406-50b01d9515c8",
                "expirationDate": "2025-10-01T00:00:00Z",
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

        let verifier = LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone())
            .expect("Verifier instantiation must work");

        let result = verifier.verify(tampered_license);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerificationError::TamperedLicense);
    }

    #[test]
    fn license_verification_with_non_rs512_signature() {
        let tampered_license = serde_json::json!({
            "license": {
                "id": "0b5b88f5-a264-4f90-8406-50b01d9515c8",
                "expirationDate": "2024-10-01T00:00:00Z",
                "customData": {
                    "owner": "John Doe"
                }
            },
            "licenseValidation": {
                "payload": "eyJpZCI6IjBiNWI4OGY1LWEyNjQtNGY5MC04NDA2LTUwYjAxZDk1MTVjOCIsImV4cGlyYXRp\
                    b25EYXRlIjoiMjAyNC0xMC0wMVQwMDowMDowMFoiLCJjdXN0b21EYXRhIjp7Im93bmVyIjoiSm9obiBE\
                    b2UifX0",
                "protected": "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9",
                "signature": "3oezad8_xfSAn2AorlW09OCh_E2ztke4ziN96wC5lSDpWoZ8gz3K3ihnmcm8ZYaDhRVOcC\
                    In3TcLpkrHz56Trw"
            }
        });

        let verifier = LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone())
            .expect("Verifier instantiation must work");

        let result = verifier.verify(tampered_license);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerificationError::VerificationFailure);
    }

    #[test]
    fn license_verification_with_tampered_signature() {
        let tampered_license = serde_json::json!({
            "license": {
                "id": "0b5b88f5-a264-4f90-8406-50b01d9515c8",
                "expirationDate": "2024-10-01T00:00:00Z",
                "customData": {
                    "owner": "John Doe"
                }
            },
            "licenseValidation": {
                "payload": "eyJpZCI6IjBiNWI4OGY1LWEyNjQtNGY5MC04NDA2LTUwYjAxZDk1MTVjOCIsImV4cGlyYXRp\
                    b25EYXRlIjoiMjAyNC0xMC0wMVQwMDowMDowMFoiLCJjdXN0b21EYXRhIjp7Im93bmVyIjoiSm9obiBE\
                    b2UifX0",
                "protected": "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9",
                "signature": "EZh1khxXXnB8bKNS4PZAOReIZ7OF0hoII5Xp-cpj6L5vwtLUOKRQAgiYymnZZDveYtzVrFyW4H\
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

        let verifier = LicenseVerifier::new(PUBLIC_KEY_JWK_JSON.clone())
            .expect("Verifier instantiation must work");

        let result = verifier.verify(tampered_license);
        let Err(error) = result else {
            panic!("An error was expected")
        };
        assert_eq!(error, LicenseVerificationError::VerificationFailure);
    }
}
