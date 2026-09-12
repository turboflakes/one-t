use crate::paseo::{
    cache_session_stats_records, fetch_asset_hub_block_hash_from_relay_chain,
    fetch_asset_hub_block_info, try_fetch_relay_chain_block_hash,
};
use log::{info, warn};
use onet_cache::{
    error::CacheError,
    types::{CacheKey, Index},
};
use onet_core::{core::Onet, error::OnetError};
use onet_records::{BlockNumber, EpochIndex};
use redis::aio::Connection;
use std::collections::HashMap;

/// Recompute and cache session stats for a list of already-elapsed sessions.
///
/// Each session's ending RC block number is read back from the `SessionByIndex` cache
/// entry (already populated live when the session rotated), and every other block hash
/// needed by `cache_session_stats_records` is re-derived from chain state, the same way
/// the live event handler does it.
pub async fn backfill_session_stats(session_indices: Vec<EpochIndex>) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let rc_rpc = onet.relay_rpc().clone();
    let ah_rpc = onet
        .asset_hub_rpc()
        .as_ref()
        .expect("AH RPC to be available")
        .clone();

    for session_index in session_indices {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
        let session_data: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(CacheKey::SessionByIndex(Index::Num(session_index.into())))
            .query_async(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        let Some(rc_block_number) = session_data
            .get("current_block")
            .and_then(|v| v.parse::<BlockNumber>().ok())
        else {
            warn!("Session {session_index} has no cached RC block number, skipping backfill");
            continue;
        };

        let rc_block_hash = try_fetch_relay_chain_block_hash(&rc_rpc, rc_block_number).await?;
        let rc_parent_block_hash =
            try_fetch_relay_chain_block_hash(&rc_rpc, rc_block_number - 1).await?;
        let ah_block_hash =
            fetch_asset_hub_block_hash_from_relay_chain(&onet, rc_block_number, rc_block_hash)
                .await?;
        let (_, ah_parent_block_hash) = fetch_asset_hub_block_info(&ah_rpc, ah_block_hash).await?;

        info!(
            "Backfilling session {session_index} (RC block #{rc_block_number}, RC hash {rc_block_hash:?}, AH hash {ah_block_hash:?})"
        );

        cache_session_stats_records(
            session_index,
            rc_block_number,
            rc_block_hash,
            rc_parent_block_hash,
            ah_block_hash,
            ah_parent_block_hash,
            false,
        )
        .await?;
    }

    Ok(())
}
