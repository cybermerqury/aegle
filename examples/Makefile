.PHONY: build certificates

build:
	cargo build

CERT_DIR=$(abspath ./certs)
MAKE_CERT=OUTPUT_DIR=$(CERT_DIR) $(MAKE) -C ./certificates/certificate_generation/

certificates:
	$(MAKE_CERT) $(CERT_DIR)/module.p12

clean_certificates:
	$(MAKE_CERT) clean_certificates

run_module_%: build
	target/debug/ppaas_module -c config/module_$*.toml

test:
	cargo test --profile release test

run_emulator: build
	RUST_LOG=info target/debug/emulator config/qkd_ab.toml
