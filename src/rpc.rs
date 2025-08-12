use std::{collections::HashMap, time::Duration};

use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::types::RawBlock;

#[derive(Clone)]
pub struct RpcClient {
    http: Client,
    url: String,
    rate_limit_per_sec: usize,
    cache: BlockCache,
}

#[derive(Clone, Default)]
struct BlockCache {
    inner: std::sync::Arc<Mutex<HashMap<u64, RawBlock>>>,
}

impl BlockCache {
    fn get(&self, h: &u64) -> Option<RawBlock> { self.inner.lock().get(h).cloned() }
    fn put(&self, h: u64, b: RawBlock) { self.inner.lock().insert(h, b); }
}

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    id: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct RpcError { code: i64, message: String }

impl RpcClient {
    pub fn new(url: String, rate_limit_per_sec: usize) -> Self {
        let http = Client::builder()
            .tcp_nodelay(true)
            .pool_max_idle_per_host(16)
            .http2_adaptive_window(true)
            .build()
            .expect("reqwest client");
        Self { http, url, rate_limit_per_sec, cache: BlockCache::default() }
    }

    pub async fn fetch_blocks_batch(&self, heights: &[u64]) -> Result<Vec<RawBlock>> {
        // Check cache first
        let mut need: Vec<u64> = Vec::new();
        let mut out: Vec<RawBlock> = Vec::new();
        for h in heights {
            if let Some(b) = self.cache.get(h) { out.push(b); } else { need.push(*h); }
        }
        if need.is_empty() { return Ok(out); }

        // Build batch: for each height, get blockhash then get block by hash with verbosity=0
        // To minimize calls, we will submit a single batch containing getblockhash for all heights,
        // then a second batch of getblock for the hashes; QuickNode supports batches.
        let hash_reqs: Vec<JsonRpcRequest> = need.iter().enumerate().map(|(i, h)| JsonRpcRequest {
            jsonrpc: "2.0",
            id: i as u64,
            method: "getblockhash",
            params: serde_json::json!([h]),
        }).collect();

        let hashes: Vec<String> = self.batch_call(hash_reqs).await?;

        let block_reqs: Vec<JsonRpcRequest> = hashes.iter().enumerate().map(|(i, hash)| JsonRpcRequest {
            jsonrpc: "2.0",
            id: i as u64,
            method: "getblock",
            params: serde_json::json!([hash, 0]),
        }).collect();

        let blocks_hex: Vec<String> = self.batch_call(block_reqs).await?;

        for (i, raw_hex) in blocks_hex.into_iter().enumerate() {
            let h = need[i];
            let hash = &hashes[i];
            let rb = RawBlock { height: h, hash: hash.clone(), raw_hex };
            self.cache.put(h, rb.clone());
            out.push(rb);
        }

        Ok(out)
    }

    async fn batch_call<T>(&self, reqs: Vec<JsonRpcRequest<'_>>) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            // rudimentary rate limiting by sleeping proportional to number of calls
            let per_sec = self.rate_limit_per_sec.max(1) as u64;
            let millis = (1000 * (reqs.len() as u64)).saturating_div(per_sec);
            if millis > 0 { sleep(Duration::from_millis(millis)).await; }

            let resp = self.http.post(&self.url).json(&reqs).send().await;
            match resp {
                Ok(r) => {
                    if r.status().as_u16() == 429 {
                        self.backoff(attempt).await;
                        continue;
                    }
                    let text = r.text().await?;
                    let v: serde_json::Value = serde_json::from_str(&text)
                        .map_err(|e| anyhow!("invalid jsonrpc response: {e}; text={}", text))?;
                    // Expect array of responses
                    let arr = v.as_array().ok_or_else(|| anyhow!("batch response not array"))?;
                    let mut out: Vec<T> = Vec::with_capacity(arr.len());
                    for item in arr {
                        if let Some(err) = item.get("error") {
                            self.handle_error(err)?;
                        }
                        let res = item.get("result").ok_or_else(|| anyhow!("missing result"))?;
                        let val: T = serde_json::from_value(res.clone())?;
                        out.push(val);
                    }
                    return Ok(out);
                }
                Err(e) => {
                    self.backoff(attempt).await;
                    if attempt > 6 { return Err(anyhow!("rpc error after retries: {e}")); }
                    continue;
                }
            }
        }
    }

    fn handle_error(&self, err: &serde_json::Value) -> Result<()> {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("");
        if code != 0 { return Err(anyhow!("rpc error {}: {}", code, msg)); }
        Ok(())
    }

    async fn backoff(&self, attempt: u32) {
        let base = 200u64;
        let delay = base.saturating_mul(1u64 << attempt.min(6));
        sleep(Duration::from_millis(delay)).await;
    }
}