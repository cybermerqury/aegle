# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

.SILENT:
.PHONY: docs view-docs

build:
	cargo build

build-tests:
	cargo test --no-run

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps --workspace

view-docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps --workspace --open

clean:
	cargo clean
