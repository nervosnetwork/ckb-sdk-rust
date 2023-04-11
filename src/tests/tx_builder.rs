use crate::tx_builder::TransactionWithScriptGroups;

#[test]
fn test_tx_with_groups_serde() {
    let raw_tx_with_groups = r#"{
        "tx_view": {
            "version": "0x0",
            "cell_deps": [
            {
                "out_point": {
                "tx_hash": "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
                "index": "0x0"
                },
                "dep_type": "dep_group"
            }
            ],
            "header_deps": [],
            "inputs": [
            {
                "since": "0x0",
                "previous_output": {
                "tx_hash": "0xea61237c75201041d8a98a936e54fb3124014510df99955448841ac6a548eea5",
                "index": "0x0"
                }
            },
            {
                "since": "0x0",
                "previous_output": {
                "tx_hash": "0xeb4276a664a8d11a32b52642bf275748ac14e6b993199ab3ef57d318eee82090",
                "index": "0x1"
                }
            }
            ],
            "outputs": [
            {
                "capacity": "0xbaa315500",
                "lock": {
                "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                "hash_type": "type",
                "args": "0x4049ed9cec8a0d39c7a1e899f0dacb8a8c28ad14"
                },
                "type": null
            },
            {
                "capacity": "0x2782e9d4c2",
                "lock": {
                "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                "hash_type": "type",
                "args": "0x4049ed9cec8a0d39c7a1e899f0dacb8a8c28ad14"
                },
                "type": null
            }
            ],
            "outputs_data": [
            "0x",
            "0x"
            ],
            "witnesses": [
            "0x5500000010000000550000005500000041000000a6352a434c833b342a7c9cdb19533df0303cfeb67f90fd8fda90437bb34a5682354ba73771f2fd627de8162d49817bef56d4cc1dfba3051272ee1e36d1a42d7400",
            "0x"
            ],
            "hash": "0x6a8680a80d7758a3846b472fb2ced62d9237641912835697cb162205b771f765"
        },
        "script_groups": [
            {
            "script": {
                "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                "hash_type": "type",
                "args": "0x4049ed9cec8a0d39c7a1e899f0dacb8a8c28ad14"
            },
            "group_type": "lock",
            "input_indices": [
                0,
                1
            ],
            "output_indices": []
            }
        ]
        }"#;

    let tx_with_groups: TransactionWithScriptGroups =
        serde_json::from_str(raw_tx_with_groups).unwrap();
    let ser_tx_with_groups1 = serde_json::to_string_pretty(&tx_with_groups).unwrap();
    // JSON encode and decode again to offset the influence to raw_tx_with_groups made by formatter,
    // it's save the effort to try to write correct raw json content.
    let tx_with_groups2: TransactionWithScriptGroups =
        serde_json::from_str(&ser_tx_with_groups1).unwrap();
    let ser_tx_with_groups2 = serde_json::to_string_pretty(&tx_with_groups2).unwrap();
    assert_eq!(ser_tx_with_groups1, ser_tx_with_groups2);
}
