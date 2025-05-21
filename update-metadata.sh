#!/bin/bash
#
# > make a file executable
# chmod +x ./update-metadata.sh
#
# > subxt-cli must be installed to update metadata
# cargo install subxt-cli --force
#
# ****** Relay Chains ******
# subxt metadata --url wss://rpc.turboflakes.io:443/westend -f bytes > packages/chains/westend/artifacts/metadata/westend_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/westend --pallets System,Session,Balances,Staking,Utility,NominationPools -f bytes > packages/chains/westend/artifacts/metadata/westend_metadata_small.scale
# subxt metadata --url wss://rpc.turboflakes.io:443/kusama -f bytes > packages/chains/kusama/artifacts/metadata/kusama_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/kusama --pallets System,Session,Balances,Staking,Utility,NominationPools -f bytes > packages/chains/kusama/artifacts/metadata/kusama_metadata_small.scale
# subxt metadata --url wss://rpc.turboflakes.io:443/polkadot -f bytes > packages/chains/polkadot/artifacts/metadata/polkadot_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/polkadot --pallets System,Session,Balances,Staking,Utility,NominationPools -f bytes > packages/chains/polkadot/artifacts/metadata/polkadot_metadata_small.scale
# subxt metadata --url wss://rpc.turboflakes.io:443/paseo -f bytes > packages/chains/paseo/artifacts/metadata/paseo_metadata.scale
#subxt metadata --url wss://rpc.turboflakes.io:443/paseo --pallets System,Session,Balances,Staking,Utility,NominationPools,Identity -f bytes > packages/chains/paseo/artifacts/metadata/paseo_metadata_small.scale
subxt metadata --url wss://dev-relay.turboflakes.io:443 -f bytes > packages/chains/westend-next/artifacts/metadata/westend_next_metadata.scale
# ****** People Chains ******
# subxt metadata --url wss://sys.turboflakes.io:443/people-westend -f bytes > packages/chains/people-westend/artifacts/metadata/people_westend_metadata.scale
# subxt metadata --url wss://sys.turboflakes.io:443/people-kusama -f bytes > packages/chains/kusama/artifacts/metadata/people_kusama_metadata.scale
# subxt metadata --url wss://sys.turboflakes.io:443/people-polkadot -f bytes > packages/chains/polkadot/artifacts/metadata/people_polkadot_metadata.scale
# subxt metadata --url wss://sys.turboflakes.io:443/people-paseo -f bytes > packages/chains/paseo/artifacts/metadata/people_paseo_metadata.scale
# ****** AssetHub Chains ******
# subxt metadata --url wss://sys.turboflakes.io:443/asset-hub-westend -f bytes > packages/chains/asset-hub-westend/artifacts/metadata/asset_hub_westend_metadata.scale
subxt metadata --url wss://dev-ah.turboflakes.io:443 -f bytes > packages/chains/asset-hub-westend-next/artifacts/metadata/asset_hub_westend_next_metadata.scale

# Generate runtime API client code from metadata. (Development mode only)

```bash
# subxt codegen --url wss://rpc.turboflakes.io:443/westend | rustfmt --edition=2018 --emit=stdout > packages/chains/westend/artifacts/metadata/westend_metadata.rs
# subxt codegen --url wss://rpc.turboflakes.io:443/asset-hub-westend | rustfmt --edition=2018 --emit=stdout > packages/chains/asset-hub-westend/artifacts/metadata/asset_hub_westend_metadata.rs
# subxt codegen --url wss://rpc.turboflakes.io:443/kusama | rustfmt --edition=2018 --emit=stdout > packages/chains/kusama/artifacts/metadata/kusama_runtime.rs
subxt codegen --url wss://dev-relay.turboflakes.io:443 | rustfmt --edition=2018 --emit=stdout > packages/chains/westend-next/artifacts/metadata/westend_next_metadata.rs
subxt codegen --url wss://dev-ah.turboflakes.io:443 | rustfmt --edition=2018 --emit=stdout > packages/chains/asset-hub-westend-next/artifacts/metadata/asset_hub_westend_next_metadata.rs
```
