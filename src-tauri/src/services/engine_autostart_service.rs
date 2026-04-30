use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt};

#[derive(Clone)]
pub struct EngineAutostartService {
    pub exe_path: String,
    pub host: String,
    pub port: u16,
}

impl EngineAutostartService {
    pub fn new(exe_path: &str, host: &str, port: u16) -> Self {
        Self {
            exe_path: exe_path.to_string(),
            host: host.to_string(),
            port,
        }
    }

    pub async fn start_if_needed(&self) -> Result<bool, String> {
        if self.is_running().await? {
            return Ok(false); // Already running
        }

        #[cfg(target_os = "windows")]
        {
            Command::new(&self.exe_path)
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .spawn()
                .map_err(|e| format!("Failed to start engine: {}", e))?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            Command::new(&self.exe_path)
                .spawn()
                .map_err(|e| format!("Failed to start engine: {}", e))?;
        }

        // Wait for it to become healthy
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if self.is_running().await? {
                return Ok(true);
            }
        }

        Err("Engine started but did not become healthy in time".to_string())
    }

    pub async fn is_running(&self) -> Result<bool, String> {
        match TcpStream::connect(format!("{}:{}", self.host, self.port)).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn post_exit_command(&self) -> Result<(), String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .await
            .map_err(|e| format!("Failed to connect for exit command: {}", e))?;

        let request = serde_json::json!({
            "type": "control",
            "payload": { "command": "exit" }
        });

        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        stream.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

        Ok(())
    }

}
