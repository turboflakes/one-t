use crate::cache::{CacheKey, Verbosity};
use crate::config::CONFIG;
use crate::errors::{CacheError, OnetError};
use crate::onet::Onet;
use crate::records::AuthorityDiscoveryKey;
use crate::records::Records;
use log::info;
use multiaddr::{Multiaddr, Protocol};
use redis::aio::Connection;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subxt::utils::H256;

type AgentVersion = String;

pub async fn try_fetch_discovery_data(
    records: &Records,
    block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();

    let config = CONFIG.clone();

    info!(
        "Start P2P discovery using {} and bootnodes {:?}",
        config.substrate_ws_url, config.discovery_bootnodes,
    );

    let (authorithy_discovery, _) =
        subp2p_explorer_cli::commands::authorities::discover_authorities(
            config.substrate_ws_url.clone(),
            format!("{:?}", api.genesis_hash()),
            config.discovery_bootnodes.clone(),
            Duration::from_secs(config.discovery_timeout),
            onet.runtime().address_format(),
            Default::default(),
        )
        .await
        .map_err(|e| OnetError::Other(format!("Cannot fetch p2p data: {:?}", e)))?;

    // debug!(
    //     "P2P DUMP {:?} ",
    //     authorithy_discovery.authority_to_details()
    // );

    // From the authority_to_details() method, we can get the IPv4 addresses of the nodes
    let mut authority_ips_map: HashMap<AuthorityDiscoveryKey, HashSet<IpAddr>> = HashMap::new();

    let authorities = authorithy_discovery.authority_to_details();
    for (authority, details) in authorities {
        for multiaddr in details {
            if let Some(ip) = get_ip_from_multiaddr(multiaddr) {
                if config.discovery_skip_ips.contains(&ip.to_string()) {
                    continue;
                }
                authority_ips_map
                    .entry(authority.clone())
                    .and_modify(|ips| {
                        (*ips).insert(ip);
                    })
                    .or_insert(HashSet::from([ip]));
            }
        }
    }

    // From the peer_info() method, we can get the agent version, listening addresses, protocols supported, etc.
    // NOTE: currently we only keep track of the agent version
    let mut authority_agent_version_map: HashMap<AuthorityDiscoveryKey, AgentVersion> =
        HashMap::new();
    let peers_data = authorithy_discovery.peer_info().clone();
    for (peer_id, info) in peers_data {
        // Get authority key from peer_id
        if let Some(peer_details) = authorithy_discovery.peer_details().get(&peer_id) {
            peer_details.authority_id();

            authority_agent_version_map
                .entry(peer_details.authority_id().clone())
                .or_insert(info.agent_version.clone());
        }
    }

    // Cache P2P data
    let mut counter = 0;
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        let current_era = records.current_era();
        let current_epoch = records.current_epoch();

        if let Some(authorities) = records.get_authorities(None) {
            for authority_idx in authorities.iter() {
                let authority_key =
                    CacheKey::AuthorityRecord(current_era, current_epoch, *authority_idx);

                if let Some(discovery_record) = records.get_discovery_record(*authority_idx, None) {
                    let mut data = discovery_record.clone();

                    if let Some(ips) =
                        authority_ips_map.get(&discovery_record.authority_discovery_key())
                    {
                        data.set_ips(Vec::from_iter(ips.clone()));
                    }

                    if let Some(agent_version) =
                        authority_agent_version_map.get(&discovery_record.authority_discovery_key())
                    {
                        if let Some((node_version, node_name)) =
                            get_node_version_and_name_from_agent_version(agent_version)
                        {
                            data.set_node_version(node_version);
                            data.set_node_name(node_name);
                        }
                    }

                    let serialized = serde_json::to_string(&data)?;
                    redis::pipe()
                        .atomic()
                        .cmd("HSET")
                        .arg(CacheKey::AuthorityRecordVerbose(
                            authority_key.to_string(),
                            Verbosity::Discovery,
                        ))
                        .arg(String::from("discovery"))
                        .arg(serialized)
                        .cmd("EXPIRE")
                        .arg(CacheKey::AuthorityRecordVerbose(
                            authority_key.to_string(),
                            Verbosity::Discovery,
                        ))
                        .arg(config.cache_writer_prunning)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;

                    counter += 1;
                }
            }
        }
    }

    // Log p2p explorer duration time
    info!("P2P stats {} cached ({:?})", counter, start.elapsed());

    Ok(())
}

fn get_ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => Some(IpAddr::V4(ip)),
        // Note: skip IPv6 for now
        // Some(Protocol::Ip6(ip)) => Some(IpAddr::V6(ip)),
        _ => None,
    }
}

fn get_node_version_and_name_from_agent_version(agent_version: &str) -> Option<(String, String)> {
    let node_name = get_node_name_from_agent_version(agent_version);
    if let Some(node_name) = node_name {
        let node_version = agent_version
            .replace(&format!("({})", node_name), "")
            .trim()
            .to_string();
        let node_name = node_name.trim().to_string();
        return Some((node_version, node_name));
    }
    None
}

fn get_node_name_from_agent_version(agent_version: &str) -> Option<String> {
    let re = Regex::new(r"\(([^)]+)\)").unwrap();
    re.captures(agent_version)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_node_name_from_agent_version() {
        let input = "Parity Polkadot/v1.16.0-87971b3e927 (some_node_name)";
        let result = get_node_name_from_agent_version(input);
        assert_eq!(result, Some("some_node_name".to_string()));

        let input = "Nothing here";
        let result = get_node_name_from_agent_version(input);
        assert_eq!(result, None);
    }
}
