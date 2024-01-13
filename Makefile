x86:
	cargo xtask build-ebpf --release
	RUSTFLAGS="-Clinker=x86_64-linux-musl-ld" cargo build --release --target=x86_64-unknown-linux-musl
arm:
	cargo xtask build-ebpf --release
	RUSTFLAGS="-Clinker=aarch64-linux-musl-ld" cargo build --release --target=aarch64-unknown-linux-musl
