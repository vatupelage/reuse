use anyhow::{anyhow, Result};
use bitcoin::{Block, Transaction, Txid};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use crate::types::RawBlock;

#[derive(Debug)]
pub struct RpcClient {
    http: Client,
    url: String,
    rate_limit_per_sec: u32,
    block_cache: BlockCache,
}

#[derive(Debug)]
struct BlockCache {
    cache: HashMap<u32, RawBlock>,
}

impl BlockCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    fn get(&self, height: u32) -> Option<&RawBlock> {
        self.cache.get(&height)
    }

    fn insert(&mut self, height: u32, block: RawBlock) {
        self.cache.insert(height, block);
    }
}

impl RpcClient {
    pub fn new(url: &str) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            url: url.to_string(),
            rate_limit_per_sec: 10, // Default rate limit
            block_cache: BlockCache::new(),
        })
    }

    pub async fn fetch_blocks_batch(&self, start_height: u32, end_height: u32) -> Result<Vec<RawBlock>> {
        let mut blocks = Vec::new();
        
        // Fetch block hashes first
        let heights: Vec<u32> = (start_height..=end_height).collect();
        let hash_requests: Vec<JsonRpcRequest> = heights
            .iter()
            .map(|&height| JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "getblockhash".to_string(),
                params: vec![serde_json::Value::Number(height.into())],
                id: height as i64,
            })
            .collect();

        let hashes_response = self.batch_call(&hash_requests).await?;
        
        // Extract block hashes
        let mut block_hashes = Vec::new();
        for response in hashes_response {
            if let Some(result) = response.result {
                if let Some(hash) = result.as_str() {
                    block_hashes.push(hash.to_string());
                }
            }
        }

        // Fetch raw blocks using hashes
        let block_requests: Vec<JsonRpcRequest> = block_hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "getblock".to_string(),
                params: vec![
                    serde_json::Value::String(hash.clone()),
                    serde_json::Value::Number(0.into()) // 0 = raw hex format
                ],
                id: i as i64,
            })
            .collect();

        let blocks_response = self.batch_call(&block_requests).await?;
        
        // Parse raw hex response (not JSON object) - getblock with verbosity=0 returns raw hex string
        for (i, response) in blocks_response.iter().enumerate() {
            if let Some(result) = &response.result {
                // getblock with verbosity=0 returns the raw hex string directly, not a nested object
                if let Some(hex_str) = result.as_str() {
                    let block = RawBlock {
                        height: start_height + i as u32,
                        hex: hex_str.to_string(),
                    };
                    blocks.push(block);
                }
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
        
        // Basic rate limiting
        let delay = Duration::from_secs(1) / self.rate_limit_per_sec;
        sleep(delay).await;
        
        let response = self.http
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            if response.status().as_u16() == 429 {
                // Rate limited - exponential backoff
                sleep(Duration::from_secs(2)).await;
                return self.batch_call(requests).await;
            }
            return Err(anyhow!("RPC request failed: {}", response.status()));
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
    id: i64,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}