use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EtwEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    pub pid: u32,
    pub tid: u32,
    pub provider: String,
    pub opcode: u16,
    pub id: u16,
    pub data: EventData,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum EventData {
    File(FileEventData),
    Process(ProcessEventData),
    Registry(RegistryEventData),
    Network(NetworkEventData),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEventData {
    #[serde(rename = "fileName")]
    pub file_name: String,
    #[serde(rename = "type")]
    pub operation_type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProcessEventData {
    #[serde(rename = "processName")]
    pub process_name: String,
    #[serde(rename = "parentPid")]
    pub parent_pid: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryEventData {
    #[serde(rename = "keyName")]
    pub key_name: String,
    #[serde(rename = "operation")]
    pub operation: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkEventData {
    #[serde(rename = "remoteAddress")]
    pub remote_address: String,
    #[serde(rename = "remotePort")]
    pub remote_port: u16,
    #[serde(rename = "protocol")]
    pub protocol: String,
}

impl EtwEvent {
    pub fn to_json(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }
}
