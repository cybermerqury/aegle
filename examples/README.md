# Examples

The examples directory contains the necessary configuration files to setup a two
node link comprising of an Alice and a Bob QKD simulated through the QKD link
simulator.
An Aegle instance for Alice and Bob is required to be launched.
A `Makefile` is provided in this directory to help in running all the necessary
components to run a this two node link.

```text
┌───────┐                        ┌───────┐
│ Aegle │<--------QUIC---------->│ Aegle │
│ Alice │                        │  Bob  │
└───────┘                        └───────┘
    │         ┌─────-----┐          │
    └---------│ QKD      │----------┘
              │ Link     │
              │ Emulator │
              └─────----─┘
```

## Requirements

To run these examples, the Rust toolchain is expected to be installed.
This setup has been tested with `rustc` version `v1.93.0`.

## Setup

1. Generate the certificates by running the below command.
   This will create the `certificates` directory with the necessary files to run
   the demo setup.

   ```shell
   make certificates
   ```

2. Launch the QKD link emulator by running

   ```shell
   make run_link_emulator
   ```

3. Launch Aegle for Alice's side by running

   ```shell
   make run_agele_alice
   ```

4. Launch Aegle for Bob's side by running

   ```shell
   make run_agele_bob
   ```

The emulator will start pushing keys to the Alice and Bob Aegle instances.
For every successful key distilled, the key id along with its binary value is
written in a csv file.
