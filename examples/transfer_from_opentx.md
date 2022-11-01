
This document is about how to use the transfer_from_opentx example to do open transaction operation.
All the addresses and keys are all in my development local node, you should not use in the production environment.
# Singhash open transaction example
1. Build an opentx address
```bash
 ./target/debug/examples/transfer_from_opentx build --receiver ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024
 ```
 The output:
 ```json
{
  "lock-arg": "0x00b398368a8ed39448f95479c1178ff3fc5e31631810",
  "lock-hash": "0x3f54ccaf46b3472b55eaa2e2c0a5cae87575b3de90a81fe60206dd5c0951ffa8",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqv8f7ak",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7"
}
```
2. Transfer capacity to the address
```bash
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
  --capacity 99 --skip-check-to-address
# 0x937deeb989bbd7f4bd0273bf2049d7614615dd58a32090b0093f23a692715871
```
3. Generate the transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 98.0 --open-capacity 1.0\
            --tx-file tx.json
```
4. Sign the transaction
```bash
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --tx-file tx.json
```
5. Add input, with capacity 98.99999588
```bash
./target/debug/examples/transfer_from_opentx add-input --tx-hash df85d2aaa44d50b1db286bdb2fbd8682cad12d6858b269d2531403ba5e63a2eb --index 0 --tx-file tx.json
```
6. Add output, capacity is 98.99999588(original) + 1(open capacity) - 0.001(fee)
```bash
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 99.99899588  --tx-file tx.json
```
7. Sign the new input
```bash
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
```
8. send the tx
```bash
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0xebb9d9ff39efbee5957d6f7d19a4a17f1ac2e69dbc9289e4931cef6b832f4d57
```

# Ethereum open transaction example
1. build an opentx address
```bash
./target/debug/examples/transfer_from_opentx build --ethereum-receiver 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d
```
output:
```json
pubkey:"038d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a"
pubkey:"048d3cfceea4f9c2e76c5c4f5e99aec74c26d6ac894648b5700a0b71f91f9b5c2a26b16aac1d5753e56849ea83bf795eb8b06f0b6f4e5ed7b8caca720595458039"
{
  "lock-arg": "0x01cf2485c76aff1f2b4464edf04a1c8045068cf7e010",
  "lock-hash": "0x057dcd204f26621ef49346ed77d2bdbf3069b83a5ef0a2b52be5299a93507cf6",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqjzc5z5",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqf4vcru"
}
```
2. Transfer capacity to the address
```bash
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgpeujgt3m2lu0jk3ryahcy58yqg5rgealqzqf4vcru \
  --capacity 99 --skip-check-to-address
# 0xbd696b87629dfe38136c52e579800a432622baf5893b61365c7a18902a9ccd60
```
3. Generate the transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx --ethereum-sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 98.0 --open-capacity 1.0\
            --tx-file tx.json
```
4. Sign the transaction
```bash
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --tx-file tx.json
```
5. Add input, with capacity 99.99899588
```bash
./target/debug/examples/transfer_from_opentx add-input --tx-hash ebb9d9ff39efbee5957d6f7d19a4a17f1ac2e69dbc9289e4931cef6b832f4d57 --index 1 --tx-file tx.json
```
6. Add output, capacity is 99.99899588(original) + 1(open capacity) - 0.001(fee)
```bash
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 100.99799588  --tx-file tx.json
```
7. Sighash sign the new input
```bash
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
```
8. Send the transaction
```bash
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0x621077216f3bf7861beacd3cdda44f7a5854454fcd133922b89f0addd0330e6b
```
# Multisig open transaction example
1. build an opentx address
```bash
./target/debug/examples/transfer_from_opentx build --require-first-n 0 \
  --threshold 2 \
  --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
  --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
  --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4                                                                                                                                                                                    14:03:11
```
The output:
```json
{
  "lock-arg": "0x065d7d0128eeaa6f9656a229b42aadd0b177d387eb10",
  "lock-hash": "0xf5202949800af0b454b2e4806c57da1d0f3ae87f7b9f4b698d9f3b71162ec196",
  "mainnet": "ckb1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqmtamce",
  "testnet": "ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqqufhe3"
}
```
2. Transfer capacity to the address
```bash
ckb-cli wallet transfer --from-account 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7 \
  --to-address ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgxt47sz28w4fhev44z9x6z4twsk9ma8pltzqqufhe3 \
  --capacity 99 --skip-check-to-address
# 0xf993b27a0129f72ec0a889cb016987c3cef00f7819461e51d5755464da6adf1b
```
3. Generate the transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx \
    --require-first-n 0 \
    --threshold 2 \
    --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
    --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
    --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4 \
    --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
    --capacity 98.0 --open-capacity 1.0 \
    --tx-file tx.json
```
4. Sign the transaction, this step can sign seperately with each sender-key
```bash
./target/debug/examples/transfer_from_opentx sign-open-tx \
    --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
    --sender-key d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc \
    --tx-file tx.json
```
5. Add input, with capacity 100.99799588
```bash
./target/debug/examples/transfer_from_opentx add-input --tx-hash 621077216f3bf7861beacd3cdda44f7a5854454fcd133922b89f0addd0330e6b --index 1 --tx-file tx.json
```
6. Add output, capacity is 100.99799588(original) + 1(open capacity) - 0.001(fee)
```bash
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 101.99699588  --tx-file tx.json
```
7. Sighash sign the new input
```bash
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
```
8. Send the tx
```bash
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0x577101b031d709992af99bd0715172bdb4d2eb7be9f11e84d6fb24ac3e1ac675
```
# Put multiple open transactions together
1. Build/sign sighash open transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 97 --open-capacity 1\
            --tx-file tx-sighash.json
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
            --tx-file tx-sighash.json
```
2. Build/sign sighash open transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx --ethereum-sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
            --capacity 97 --open-capacity 1\
            --tx-file tx-ethereum.json
./target/debug/examples/transfer_from_opentx sign-open-tx --sender-key 63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d \
            --tx-file tx-ethereum.json
```
3. Build/sign multisig open transaction
```bash
./target/debug/examples/transfer_from_opentx gen-open-tx \
    --require-first-n 0 \
    --threshold 2 \
    --sighash-address ckt1qyqt8xpk328d89zgl928nsgh3lelch33vvvq5u3024 \
    --sighash-address ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 \
    --sighash-address ckt1qyqywrwdchjyqeysjegpzw38fvandtktdhrs0zaxl4 \
    --receiver ckt1qqwmhmsv9cmqhag4qxguaqux05rc4qlyq393vu45dhxrrycyutcl6qgqkwvrdz5w6w2y372508q30rlnl30rzccczqhsaju7 \
    --capacity 97 --open-capacity 1.0 \
    --tx-file tx-multisig.json
./target/debug/examples/transfer_from_opentx sign-open-tx \
    --sender-key 8dadf1939b89919ca74b58fef41c0d4ec70cd6a7b093a0c8ca5b268f93b8181f \
    --sender-key d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc \
    --tx-file tx-multisig.json
```
4. merge into one transaction

You can merge them in one command:
```bash
./target/debug/examples/transfer_from_opentx merge-open-tx \
    --in-tx-file tx-sighash.json \
    --in-tx-file tx-ethereum.json \
    --in-tx-file tx-multisig.json \
    --tx-file tx.json
```
 The other way get the same merge result:
+ Merge first 2, then merge the last
```bash
./target/debug/examples/transfer_from_opentx merge-open-tx \
    --in-tx-file tx-sighash.json \
    --in-tx-file tx-ethereum.json \
    --tx-file tx.json
./target/debug/examples/transfer_from_opentx merge-open-tx \
    --in-tx-file tx.json \
    --in-tx-file tx-multisig.json \
    --tx-file tx.json
```
+ Merge last 2, then merge the first
```bash
./target/debug/examples/transfer_from_opentx merge-open-tx \
    --in-tx-file tx-ethereum.json \
    --in-tx-file tx-multisig.json \
    --tx-file tx.json
./target/debug/examples/transfer_from_opentx merge-open-tx \
    --in-tx-file tx-sighash.json \
    --in-tx-file tx.json \
    --tx-file tx.json
```
5. Add input, with capacity 101.99699588
```bash
./target/debug/examples/transfer_from_opentx add-input --tx-hash 577101b031d709992af99bd0715172bdb4d2eb7be9f11e84d6fb24ac3e1ac675 --index 1 --tx-file tx.json
```
6. Add output, capacity is 101.99699588(original) + 3(1 open capacity each) - 0.001(fee)
```bash
./target/debug/examples/transfer_from_opentx add-output --to-address ckt1qyqy68e02pll7qd9m603pqkdr29vw396h6dq50reug --capacity 104.99599588  --tx-file tx.json
```
7. Sighash sign the new input
```bash
./target/debug/examples/transfer_from_opentx sighash-sign-tx --sender-key 7068b4dc5289353c688e2e67b75207eb5574ba4938091cf5626a4d0f5cc91668 --tx-file tx.json
```
8. Send the transaction
```bash
./target/debug/examples/transfer_from_opentx send --tx-file tx.json
# 0x4fd5d4adfb009a6e342a9e8442ac54989e28ef887b1fec60c3703e4c4d223b39
```