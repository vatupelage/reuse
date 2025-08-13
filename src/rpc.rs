use anyhow::{anyhow, Result};
use bitcoin::{Transaction, Txid};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::types::RawBlock;

#[derive(Debug, Clone)]
pub struct RpcClient {
    http: Client,
    url: String,
}

impl RpcClient {
    pub fn new(url: &str) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            url: url.to_string(),
        })
    }

    pub async fn fetch_blocks_batch(&self, start_height: u32, end_height: u32) -> Result<Vec<RawBlock>> {
        let mut blocks = Vec::new();
        
        for height in start_height..=end_height {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "getblock".to_string(),
                params: vec![
                    serde_json::Value::String(height.to_string()),
                    serde_json::Value::Number(0.into()), // 0 = hex format
                ],
                id: height as i64,
            };

            let responses = self.batch_call(&[request]).await?;
            
            if let Some(response) = responses.first() {
                // CRITICAL FIX: Check for RPC errors in the response
                if let Some(error) = &response.error {
                    return Err(anyhow!("RPC error at block {}: {:?}", height, error));
                }
                
                if let Some(result) = &response.result {
                    if let Some(hex_str) = result.as_str() {
                        let block = RawBlock {
                            height,
                            hex: hex_str.to_string(),
                        };
                        blocks.push(block);
                    } else {
                        return Err(anyhow!("Invalid response format for block {}", height));
                    }
                } else {
                    return Err(anyhow!("No result returned for block {}", height));
                }
            } else {
                return Err(anyhow!("No response received for block {}", height));
            }
        }
        
        Ok(blocks)
    }

    pub async fn get_transaction(&self, txid: &Txid) -> Result<Transaction> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "getrawtransaction".to_string(),
            params: vec![
                serde_json::Value::String(txid.to_string()),
                serde_json::Value::Bool(false), // verbose = false to get raw hex
            ],
            id: 1,
        };

        let responses = self.batch_call(&[request]).await?;
        
        if let Some(response) = responses.first() {
            // CRITICAL FIX: Check for RPC errors in the response
            if let Some(error) = &response.error {
                return Err(anyhow!("RPC error for transaction {}: {:?}", txid, error));
            }
            
            if let Some(result) = &response.result {
                if let Some(hex_str) = result.as_str() {
                    let tx_bytes = hex::decode(hex_str)?;
                    let tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes)?;
                    Ok(tx)
                } else {
                    Err(anyhow!("Invalid response format for getrawtransaction"))
                }
            } else {
                Err(anyhow!("No result in getrawtransaction response"))
            }
        } else {
            Err(anyhow!("No response received for getrawtransaction"))
        }
    }

    async fn batch_call(&self, requests: &[JsonRpcRequest]) -> Result<Vec<JsonRpcResponse<serde_json::Value>>> {
        let request_body = serde_json::to_string(&requests)?;
        
        let response = self.http
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let response_text = response.text().await?;
        let responses: Vec<JsonRpcResponse<serde_json::Value>> = serde_json::from_str(&response_text)?;
        
        Ok(responses)
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: i64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}