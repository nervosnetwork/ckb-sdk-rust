# -D clippy::fallible_impl_from
CLIPPY_OPTS := -D warnings -D clippy::clone_on_ref_ptr -D clippy::enum_glob_use \
	-A clippy::mutable_key_type -A clippy::upper_case_acronyms

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all --all-targets --all-features -- ${CLIPPY_OPTS}

test:
	RUST_BACKTRACE=full cargo test --all --all-features

ci: fmt clippy test security-audit check-crates check-licenses

security-audit: ## Use cargo-deny to audit Cargo.lock for crates with security vulnerabilities.
	cargo deny check --hide-inclusion-graph --show-stats advisories sources

check-crates: ## Use cargo-deny to check specific crates, detect and handle multiple versions of the same crate and wildcards version requirement.
	cargo deny check --hide-inclusion-graph --show-stats bans

check-licenses: ## Use cargo-deny to check licenses for all dependencies.
	cargo deny check --hide-inclusion-graph --show-stats licenses

.PHONY: test clippy fmt ci security-audit check-crates check-licenses
