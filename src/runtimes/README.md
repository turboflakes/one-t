## Supported Runtimes
  - Polkadot
  - Kusama
  - Westend

TODO: Improve the runtimes implementation without the need of replicating the same functions for each runtime. Note that *RuntimeApi* is runtime specific. It gives access to api functions specific for each runtime. 

## Generated files from subxt-cli 

Download metadata from a substrate node, for use with `subxt` codegen.

```bash
# Relay Chains
subxt metadata --url wss://rpc.turboflakes.io:443/westend -f bytes > ./metadata/westend_metadata.scale
subxt metadata --url wss://rpc.turboflakes.io:443/paseo -f bytes > ./metadata/paseo_metadata.scale
subxt metadata --url wss://rpc.turboflakes.io:443/kusama -f bytes > ./metadata/kusama_metadata.scale
subxt metadata --url wss://rpc.turboflakes.io:443/polkadot -f bytes > ./metadata/polkadot_metadata.scale
# People Chains
subxt metadata --url wss://sys.turboflakes.io:443/people-westend -f bytes > ./metadata/people_westend_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-paseo -f bytes > ./metadata/people_paseo_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-kusama -f bytes > ./metadata/people_kusama_metadata.scale
subxt metadata --url wss://sys.turboflakes.io:443/people-polkadot -f bytes > ./metadata/people_polkadot_metadata.scale
```

Generate runtime API client code from metadata.

```bash
subxt codegen --url wss://rpc.turboflakes.io:443/westend | rustfmt --edition=2018 --emit=stdout > westend_metadata.rs
subxt codegen --url wss://rpc.turboflakes.io:443/kusama | rustfmt --edition=2018 --emit=stdout > kusama_runtime.rs
subxt codegen --url wss://rpc.turboflakes.io:443/polkadot | rustfmt --edition=2018 --emit=stdout > polkadot_runtime.rs
```
