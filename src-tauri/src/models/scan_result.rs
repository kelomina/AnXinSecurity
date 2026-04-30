use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanResult {
    #[serde(rename = "fileId")]
    pub file_id: String,
    pub verdict: Verdict,
    #[serde(rename = "threatType", skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Malware,
    Suspicious,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanOptions {
    #[serde(rename = "maxFileSizeMB", skip_serializing_if = "Option::is_none")]
    pub max_file_size_mb: Option<u64>,
    #[serde(rename = "commonExtensionsOnly", skip_serializing_if = "Option::is_none")]
    pub common_extensions_only: Option<bool>,
}
