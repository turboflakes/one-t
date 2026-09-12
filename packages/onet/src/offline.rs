use log::{error, info};
use onet_chains::SupportedRuntime;
use onet_config::CONFIG;
use onet_kusama::offline as kusama_offline;
use onet_paseo::offline as paseo_offline;
use onet_polkadot::offline as polkadot_offline;

/// Parses a `13795,13796,13800-13802` value into a sorted, deduped list of session indices.
pub fn parse_backfill_sessions(raw: &str) -> Vec<u32> {
    let mut indices: Vec<u32> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if let Some((start, end)) = token.split_once('-') {
            let start: u32 = start.trim().parse().expect("invalid session range start");
            let end: u32 = end.trim().parse().expect("invalid session range end");
            indices.extend(start..=end);
        } else if !token.is_empty() {
            indices.push(token.parse().expect("invalid session index"));
        }
    }
    indices.sort_unstable();
    indices.dedup();
    indices
}

/// Recompute and cache session stats for a list of already-elapsed sessions, without
/// starting the event-subscription pipeline, Matrix, or API server.
pub async fn backfill_sessions(session_indices: Vec<u32>) {
    let config = CONFIG.clone();
    info!("Backfilling session stats for {:?}", session_indices);
    let result = match SupportedRuntime::from(config.chain_name) {
        SupportedRuntime::Polkadot => {
            polkadot_offline::backfill_session_stats(session_indices).await
        }
        SupportedRuntime::Kusama => kusama_offline::backfill_session_stats(session_indices).await,
        SupportedRuntime::Paseo => paseo_offline::backfill_session_stats(session_indices).await,
        runtime => {
            error!("Session stats backfill is not supported for {runtime}");
            return;
        }
    };
    if let Err(e) = result {
        error!("backfill_session_stats error: {}", e);
    }
}
