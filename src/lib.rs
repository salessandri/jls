pub mod verification;

use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};
use serde_json;
use uuid::Uuid;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct License {
    pub id: Uuid,
    #[serde(rename = "expirationDate")]
    pub expiration_date: DateTime<Utc>,
    #[serde(rename = "customData")]
    pub custom_data: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiableLicense {
    license: License,
    #[serde(rename = "licenseValidation")]
    license_validation: serde_json::Value,
}
