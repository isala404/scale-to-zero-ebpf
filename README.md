# scale-to-zero

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## TODOs

- [ ] Add multi namespace support 
    - currently only default namespace is supported
- [ ] Move the scaling logic to a central operator
    - currently will only work in single node clusters
- [ ] Hold the request till the pod is healthy
    - as of now the requests will fail if the pod takes longer to start
