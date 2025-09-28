test: lint
	cargo test

lint:
	cargo fmt --message-format human -- --check
	cargo check
	cargo clippy -q --no-deps -- -D warnings

clean:
	cargo clean