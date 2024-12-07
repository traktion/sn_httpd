/*use std::collections::HashSet;
use std::sync::Arc;
use autonomi::Client;
use autonomi::client::{Amount, ClientEvent, UploadSummary};
use autonomi::client::data::{ChunkAddr, CostError, DataAddr, GetError, PutError, CHUNK_UPLOAD_BATCH_SIZE};
use bytes::Bytes;
use sn_evm::{AttoTokens, EvmWallet};
use sn_protocol::NetworkAddress;
use sn_protocol::storage::{try_deserialize_record, Chunk, ChunkAddress, RecordHeader, RecordKind};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct CachingClient {
    client: Client,
}

impl CachingClient {
    /// Fetch a blob of data from the network
    pub async fn data_get(&self, addr: DataAddr) -> Result<Bytes, GetError> {
        let data_map_chunk = self.client.chunk_get(addr).await?;
        let data = self
            .fetch_from_data_map_chunk(data_map_chunk.value())
            .await?;

        Ok(data)
    }
}*/