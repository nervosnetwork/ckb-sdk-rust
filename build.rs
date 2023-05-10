use std::path::PathBuf;

fn get_hash_size() -> usize {
    128
}

fn get_hash_option() -> &'static str {
    "f"
}

fn get_hash_info() -> (&'static str, Vec<&'static str>) {
    let thash_file = "../deps/sphincsplus/ref/thash_shake_simple.c";

    (
        "shake",
        vec![
            "../deps/sphincsplus/ref/fips202.c",
            "../deps/sphincsplus/ref/hash_shake.c",
            thash_file,
        ],
    )
}

fn get_os_specic_src_files() -> Vec<&'static str> {
    let mut files = vec![];

    if !cfg!(windows) {
        files.push("../deps/sphincsplus/ref/randombytes.c");
    }

    files
}

fn main() {
    let mut source_list = vec![
        "../deps/sphincsplus/ref/address.c",
        "../deps/sphincsplus/ref/merkle.c",
        "../deps/sphincsplus/ref/wots.c",
        "../deps/sphincsplus/ref/wotsx1.c",
        "../deps/sphincsplus/ref/utils.c",
        "../deps/sphincsplus/ref/utilsx1.c",
        "../deps/sphincsplus/ref/fors.c",
        "../deps/sphincsplus/ref/sign.c",
        "ckb-sphincsplus.c",
    ];

    let (hash_name, mut hash_src_files) = get_hash_info();

    source_list.append(&mut hash_src_files);
    source_list.append(&mut get_os_specic_src_files());
    let define_param = format!(
        "sphincs-{}-{}{}",
        hash_name,
        get_hash_size(),
        get_hash_option()
    );

    let c_src_dir = PathBuf::from("deps/quantum-resistant-lock-script/c/");

    let mut builder = cc::Build::new();
    builder.define("PARAMS", define_param.as_str());
    builder.include(&c_src_dir);
    builder.include(
        &c_src_dir
            .join("..")
            .join("deps")
            .join("sphincsplus")
            .join("ref"),
    );

    for source in source_list {
        builder.file(c_src_dir.join(source));
    }
    builder.compile("sphincsplus");
}
