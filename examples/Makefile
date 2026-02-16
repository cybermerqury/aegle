.SILENT:
.PHONY: run_aegle_alice run_aegle_bob run_link_emulator certificates clean_logs clean

CERT_DIR=$(abspath ./certificates)

run_aegle_alice:
	RUST_LOG=INFO cargo run --bin=aegle -- --config-file=config/alice.toml

run_aegle_bob:
	RUST_LOG=INFO cargo run --bin=aegle -- --config-file=config/bob.toml

run_link_emulator:
	RUST_LOG=INFO cargo run --bin=emulator config/qkd_link_alice_bob.toml

certificates: $(CERT_DIR)/module.pem

# Variables
ROOT_CRT = $(CERT_DIR)/root.pem
ROOT_KEY  = $(CERT_DIR)/root.key
LOG = $(CERT_DIR)/output.log
SERIAL_NUM = 1

dir_guard=@mkdir -p $(CERT_DIR)

%.pem: %.csr %.ext $(ROOT_CRT)
	$(dir_guard)

	echo "Signing the certificate '$@'. Please enter the password you used to" \
		 "protect the root certificate"

	printf "Generating certificate '%s' with serial '%d' signed using '%s'...\n" $@ $(SERIAL_NUM) $(ROOT_CRT) \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	openssl x509 -req               \
 		-in $(word 1,$^)            \
		-CA $(ROOT_CRT)             \
 		-CAkey $(ROOT_KEY)          \
 		-set_serial $(SERIAL_NUM)   \
 		-days 365                   \
 		-extfile $(basename $@).ext \
 		-out $@                     \
		2>&1 | ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	cat $(basename $@).key >> $@

	printf "Certificate '%s' generated\n" $@ \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	$(eval SERIAL_NUM=$(shell echo $$(($(SERIAL_NUM)+1))))

%.csr:
	$(dir_guard)

	printf "Generating certificate signing request for '%s'...\n" $@ \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	openssl req                                              \
 		-newkey rsa:4096                                     \
 		-nodes                                               \
 		-days 365                                            \
 		-subj "/C=MT/O=Merqury Cybersecurity Limited/CN=$(basename $(notdir $@))" \
 		-keyout $(basename $@).key                           \
 		-out $@                                              \
		2>&1 | ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	printf "Certificate '%s' signing request generated\n" $@ \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

%.ext:
	$(dir_guard)
	echo "subjectAltName = DNS:localhost,IP:127.0.0.1" >> $@

$(ROOT_CRT):
	$(dir_guard)

	echo "Generating password protected root certificate. Make sure the" \
		  "password is at least 4 characters or certificate generation"  \
		  "fails."

	printf "Generating the root certificate '%s'...\n" $(ROOT_CRT) \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	openssl req -x509                                            \
		-newkey rsa:4096                                         \
		-days 365                                                \
		-subj "/C=MT/CN=www.merqury.eu/O=Merqury\ Cybersecurity" \
		-keyout $(ROOT_KEY)                                      \
		-out $@                                                  \
		2>&1 | ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

	printf "Root certificate '%s' generated.\n" $(ROOT_CRT) \
		| ts '%d-%m-%Y %H:%M:%S' >> $(LOG) 2>&1

clean_logs:
	rm -rf app_alice.json.* app_bob.json.* module_a.json.*

clean: clean_logs
	rm -rf $(CERT_DIR)/
