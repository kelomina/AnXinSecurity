use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct EngineService {
    host: String,
    port: u16,
}

impl EngineService {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    pub async fn health_check(&self) -> Result<serde_json::Value, String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .await
            .map_err(|e| format!("Failed to connect to engine: {}", e))?;

        // 发送健康检查请求（4字节长度前缀 + JSON）
        let request = serde_json::json!({"type": "health"});
        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        stream.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

        // 读取响应
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await.map_err(|e| e.to_string())?;

        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(response)
    }

    pub async fn scan_file(
        &self,
        file_path: &str,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .await
            .map_err(|e| format!("Failed to connect to engine: {}", e))?;

        let request = serde_json::json!({
            "type": "scan",
            "path": file_path,
            "options": options
        });

        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        stream.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

        // 读取响应
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await.map_err(|e| e.to_string())?;

        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(response)
    }

    pub async fn scan_batch(
        &self,
        file_paths: &[String],
        options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .await
            .map_err(|e| format!("Failed to connect to engine: {}", e))?;

        let request = serde_json::json!({
            "type": "batch_scan",
            "paths": file_paths,
            "options": options
        });

        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        stream.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

        // 读取响应
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
        let response_len = u32::from_le_bytes(len_buf) as usize;

        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await.map_err(|e| e.to_string())?;

        let response: serde_json::Value = serde_json::from_slice(&response_buf)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(response)
    }
}
