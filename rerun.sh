cd probes/ && cargo bpf build --target-dir=../target && cd - && cargo build --bin xdp && sudo ./target/debug/xdp
