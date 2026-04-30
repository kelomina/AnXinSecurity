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

    /// 函数名称：cancel_scan
    /// 函数作用：向扫描引擎发送取消扫描请求。仅尝试发送请求，不等待响应。
    /// Purpose: Sends a cancel scan request to the scan engine. Fire-and-forget, does not wait for response.
    /// 调用方：commands::scanner::cancel_scan
    /// Called by: commands::scanner::cancel_scan
    /// 中文关键词：取消扫描，中断，TCP通信，引擎命令
    /// English keywords: cancel scan, abort, TCP communication, engine command
    pub async fn cancel_scan(&self) -> Result<bool, String> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .await
            .map_err(|e| format!("Failed to connect to engine for cancel: {}", e))?;

        let request = serde_json::json!({"type": "cancel"});
        let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        let len = request_bytes.len() as u32;

        stream.write_all(&len.to_le_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&request_bytes).await.map_err(|e| e.to_string())?;

        // 不等待响应，仅尝试发送
        // Do not wait for response, fire-and-forget
        Ok(true)
    }

    /// 函数名称：scan_batch
    /// 函数作用：批量扫描多个文件，依次发到引擎并汇总结果。
    /// Purpose: Scans multiple files in batch, sends to engine sequentially and aggregates results.
    /// 调用方：commands::scanner::scan_batch
    /// Called by: commands::scanner::scan_batch
    /// 中文关键词：批量扫描，多文件扫描，TCP通信，引擎通信
    /// English keywords: batch scan, multi-file scan, TCP communication, engine communication
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
