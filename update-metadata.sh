#!/bin/bash
#
# > make a file executable
# chmod +x ./update-metadata.sh
#
# > subxt-cli must be installed to update metadata
# cargo install subxt-cli --force
#
# Relay Chains
subxt metadata --url wss://rpc.turboflakes.io:443/kusama -f bytes > packages/chains/kusama/artifacts/metadata/kusama_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/kusama --pallets System,Session,Balances,Staking,Utility,NominationPools -f bytes > packages/chains/kusama/artifacts/metadata/kusama_metadata_small.scale
subxt metadata --url wss://rpc.turboflakes.io:443/polkadot -f bytes > packages/chains/polkadot/artifacts/metadata/polkadot_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/polkadot --pallets System,Session,Balances,Staking,Utility,NominationPools -f bytes > packages/chains/polkadot/artifacts/metadata/polkadot_metadata_small.scale
subxt metadata --url wss://rpc.turboflakes.io:443/paseo -f bytes > packages/chains/paseo/artifacts/metadata/paseo_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/paseo --pallets System,Session,Balances,Staking,Utility,NominationPools,Identity -f bytes > packages/chains/paseo/artifacts/metadata/paseo_metadata_small.scale
# People Chains
#subxt metadata --url wss://sys.turboflakes.io:443/people-westend -f bytes > packages/chains/westend/artifactsmetadata/people_westend_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-kusama -f bytes > packages/chains/kusama/artifacts/metadata/people_kusama_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-polkadot -f bytes > packages/chains/polkadot/artifacts/metadata/people_polkadot_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-paseo -f bytes > packages/chains/paseo/artifacts/metadata/people_paseo_metadata.scale
