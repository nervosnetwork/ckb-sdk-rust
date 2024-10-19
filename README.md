
# CKB SDK Rust

The Rust SDK for Nervos [CKB][ckb] provides several essential features for developers:

- RPC access to CKB nodes
- Data structure definitions for various concepts within CKB
- Support for assembling CKB transactions
- Signature unlocking support for commonly used [lock scripts](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#lock-script).

These features allow for seamless interaction with CKB and facilitate the development of decentralized applications on the CKB network.

## Install

```toml
# Cargo.toml
[dependencies]
ckb-sdk = "3.4"
```

## Build

Build:

```bash
cargo build
```

Run unit tests:

```
make test
```

Please refer to the [Makefile](./Makefile) for more compilation commands.

## Quick start

### Setup

ckb-sdk-rust provides a convenient client that enables you to easily interact with CKB nodes.

```rust
use ckb_sdk::rpc::CkbRpcClient;

let mut ckb_client = CkbRpcClient::new("https://testnet.ckb.dev");
let block = ckb_client.get_block_by_number(0.into()).unwrap();
println!("block: {}", serde_json::to_string_pretty(&block).unwrap());
```

For more details about CKB RPC APIs, please refer to the [CKB RPC doc](https://github.com/nervosnetwork/ckb/blob/master/rpc/README.md).

### Build transaction by manual

The following code example demonstrates how to construct a transfer transaction on CKB. You can use it to transfer a specified amount of CKB from one address to another.

**NOTE**: The address and key are for demo purposes only and should not be used in a production environment.

```rust
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, HumanCapacity, ScriptId,
};
use ckb_types::{
    bytes::Bytes,
    core::BlockView,
    h256,
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
};
use std::{collections::HashMap, str::FromStr};

// Prepare the necessary data for a CKB transaction:
//   * set the RPC endpoint for the testnet
//   * define the sender's address and secret key
//   * define the recipient's address
//   * specify the capacity to transfer
let ckb_rpc = "https://testnet.ckb.dev:8114";
let sender = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqf7v2xsyj0p8szesqrwqapvvygpc8hzg9sku954v").unwrap();
let sender_key = secp256k1::SecretKey::from_slice(
    h256!("0xef4dfe655b3df20838bdd16e20afc70dfc1b9c3e87c54c276820315a570e6555").as_bytes(),
)
.unwrap();
let receiver = Address::from_str("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvglkprurm00l7hrs3rfqmmzyy3ll7djdsujdm6z").unwrap();
let capacity = HumanCapacity::from_str("100.0").unwrap();

 // Build ScriptUnlocker
let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
let mut unlockers = HashMap::default();
unlockers.insert(
    sighash_script_id,
    Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
);

// Build CapacityBalancer
let placeholder_witness = WitnessArgs::new_builder()
    .lock(Some(Bytes::from(vec![0u8; 65])).pack())
    .build();
let balancer = CapacityBalancer::new_simple(sender.payload().into(), placeholder_witness, 1000);

// Build:
//   * CellDepResolver
//   * HeaderDepResolver
//   * CellCollector
//   * TransactionDependencyProvider
let mut ckb_client = CkbRpcClient::new(ckb_rpc);
let cell_dep_resolver = {
    let genesis_block = ckb_client.get_block_by_number(0.into()).unwrap().unwrap();
    DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block)).unwrap()
};
let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

// Build the transaction
let output = CellOutput::new_builder()
    .lock(Script::from(&receiver))
    .capacity(capacity.0.pack())
    .build();
let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
let (_tx, _) = builder
    .build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )
    .unwrap();
```

### Generate a new address

In CKB, a private key can be used to generate a public key, which is then hashed using the Blake2b hashing algorithm to produce a CKB address. The public key is derived from the private key using the secp256k1 elliptic curve cryptography algorithm. This process results in a unique CKB address that can be used to receive or send CKB tokens. It is important to keep the private key secure, as anyone with access to it can potentially access the associated CKB funds.

```rust
use ckb_sdk::types::{Address, AddressPayload, NetworkType};
use rand::Rng;

let mut rng = rand::thread_rng();
let privkey_bytes: [u8; 32] = rng.gen();
let secp_secret_key = secp256k1::SecretKey::from_slice(&privkey_bytes).unwrap();
let pubkey =
    secp256k1::PublicKey::from_secret_key(&ckb_crypto::secp::SECP256K1, &secp_secret_key);
let payload = AddressPayload::from_pubkey(&pubkey);
let address = Address::new(NetworkType::Mainnet, payload, true);
println!("address: {}", address.to_string());
```

### Parse address

In the world of CKB, a lock script can be represented as an address. It is possible to parse an address from an encoded string and then obtain its network and script.

```rust
use ckb_sdk::types::Address;
use ckb_types::packed::Script;
use std::str::FromStr;

let addr_str = "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqgvf0k9sc40s3azmpfvhyuudhahpsj72tsr8cx3d";
let addr = Address::from_str(addr_str).unwrap();
let _network = addr.network();
let _script: Script = addr.payload().into();
```

For more details please about CKB address refer to [CKB rfc 0021](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md).


## More Examples

* [`transfer_from_sighash.rs`](examples/transfer_from_sighash.rs) Transfer capacity from a sighash address
* [`transfer_from_multisig.rs`](examples/transfer_from_multisig.rs) Transfer capacity from a multisig address (main logic is less than 60 lines of code)

You can try compiling them by running the following command in your terminal:

```sh
cargo build --examples
```

For more use cases of building transactions with CKB node, please refer to [these examples](./examples/) and [unit tests](./src/tests/).

## License

The SDK is available as open source under the terms of the [MIT License](./LICENSE).

## ChangeLog

See [CHANGELOG](CHANGELOG.md) for more details.


[ckb]: https://github.com/nervosnetwork/ckb
