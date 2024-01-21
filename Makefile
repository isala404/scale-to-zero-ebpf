x86:
	cargo xtask build-ebpf --release
	RUSTFLAGS="-Clinker=x86_64-linux-musl-ld" cargo build --release --target=x86_64-unknown-linux-musl
	docker build . -t supiri/scale-to-zero:latest -f Dockerfile.dev
arm:
	cargo xtask build-ebpf --release
	RUSTFLAGS="-Clinker=aarch64-linux-musl-ld" cargo build --release --target=aarch64-unknown-linux-musl
	docker build . -t supiri/scale-to-zero:latest-arm -f Dockerfile.dev.arm
