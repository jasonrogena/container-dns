export RUST_BACKTRACE ?= 1
export CARGO_BUILD_ARGS ?= --verbose --release

dependencies:
	rustup component add cargo
	rustup component add clippy
	rustup component add rustfmt

clean:
	git clean -x -f tests/tmp
	cargo clean

test: dependencies
	cargo clippy --all-targets --all-features -- -D warnings -D unused_imports
	cargo fmt --all -- --check
	cargo test

coverage: dependencies
	rustup component add llvm-tools-preview
	cargo install cargo-llvm-cov
	cargo llvm-cov --all-features --workspace --lcov --output-path target/lcov.info

fmt: dependencies
	cargo fmt

build: dependencies clean
	cargo build ${CARGO_BUILD_ARGS}

release: dependencies
	cross build --release --target $(TARGET)
