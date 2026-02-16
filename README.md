# AEGLE - A quantum post processing stack

- [AEGLE - A quantum post processing stack](#aegle---a-quantum-post-processing-stack)
  - [Background and motivation](#background-and-motivation)
  - [Architecture overview](#architecture-overview)
    - [Core](#core)
      - [Key State Machine](#key-state-machine)
    - [Pipeline traits](#pipeline-traits)
  - [Application](#application)
    - [Communication layer](#communication-layer)
    - [Error correction](#error-correction)
      - [Cascade](#cascade)
      - [Binary LDPC](#binary-ldpc)
      - [Non-binary LDPC](#non-binary-ldpc)
    - [Pipeline assembly and executiion](#pipeline-assembly-and-executiion)
  - [Contact us](#contact-us)
  - [License](#license)

## Background and motivation

After the quantum transmission phase, the two communicating parties, commonly
referred to as Alice and Bob, each hold a “sifted” key.
This key consists of bits that were measured in compatible bases, but due to
channel noise and detector imperfections, a small fraction of bits will differ
between the two parties.
The objective of post-processing is to reconcile these discrepancies and
eliminate any information that might have leaked to a potential eavesdropper,
producing a final key suitable for cryptographic use.
Post-processing proceeds over an authenticated but public classical channel.
The adversary may read but cannot alter messages.
The core of the stack assumes that authentication is provided externally and
focuses on correctness and safety of the reconciliation and
privacy-amplification pipeline, whereas the module executable uses autheticated
QUIC streams for classical communication.
The software leverages Rust's type system and ownership model to guarantee that
keys cannot exist in inconsistent states and that pipelines are assembled
correctly at compile time.
It also provides a modular architecture, enabling alternative reconciliation
algorithms other than the currently implemented Cascade and LDPC to be
integrated easily.

## Architecture overview

The repository is organized into several packages:

```
aegle
├── core           # Traits, key state machine, and error definitions
├── app            # Executable QKD node (leader/follower roles)
├── cascade        # Cascade error correction algorithm
├── bin_ldpc       # Binary LDPC error correction
├── nonbinary_ldpc # Nonbinary LDPC error correction
└── benchmark      # Performance and correctness evaluation tools
```

Each crate has a well-defined role.
The core crate defines shared interfaces, including the state machine that
models a key’s evolution through the pipeline.
The module crate provides the runtime executable that coordinates communication
and orchestrates the steps of the pipeline.
Algorithm-specific reconciliation is implemented in separate crates such as
cascade and ldpc.
Finally, the benchmark crate exercises these components to measure throughput,
bit error rates and frame error rates.

### Core

The core crate defines common data structures and abstractions used throughout the system.
Its source structure is:

```
core/src
├── errors.rs
├── key_state_machine.rs
├── lib.rs
├── models.rs
└── traits.rs
```

#### Key State Machine

The file `key_state_machine.rs` defines the Key type and the logic that
transitions it between states.
Unlike a phantom-typed placeholder, the state in this implementation carries
data relevant to that stage of processing.
The central part of code is shown below.

```rust
// Key States

#[derive(Serialize, Deserialize, Default)]
pub struct Sifted {
    leaked_bits: usize,
}

#[derive(Serialize, Deserialize)]
pub struct PartiallyRevealed {
    pub revealed_bits: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct Reconciling {
    pub revealed_bits: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct Reconciled {
    pub leaked_bits: usize,
    pub actual_error: f64,
}

// Main Key struct

#[derive(Serialize, Deserialize)]
pub struct Key<T> {
   device_id: DeviceId,
    key_id: KeyId,
    data: KeyData, // A wrapper around a bit vector
    state: T,
}

// ...
```

Here, each key state (Sifted, PartiallyRevleaed, Reconciled, etc. ) is a
separate struct defined under `models.rs`.
Each PostProcessingStep implementation consumes one key in some state state and
produces another, ensuring that invalid transitions are impossible.
Because the Key type carries actual data rather than a marker, each state may
contain the attributes relevant to that processing stage, such as error rates
and the indicie of leaked bits.
The actual transition is handled via specific impl methods for particular states
as shown below.

```rust
impl Key<Sifted> {
    pub fn verify(self) -> Key<Verified> {
        // consume sifted key and create a `Verified` key
    }

    // ...
}

impl Key<Verified> {
    pub fn start_reconciliation(self) -> Key<Reconciling> {
        Key {
            data: self.data,
            key_id: self.key_id,
            device_id: self.device_id,
            state: Reconciling {
                revealed_bits: Vec::new(),
            },
        }
    }

    // ...
}

// And so on
```

### Pipeline traits

The traits govern how each post-processing stage is constructed, executed, and
chained together.
_PostProcessingSetup_ and _PostProcessingStep_ form the generic interface
through which the leader orchestrates a pipeline of classical post-processing
algorithms, such as reconciliation and privacy amplification.
They define both the lifecycle of a processing step and the way information is
exchanged between pipeline stages and network peers.

The definitions from the core source code is shown below.

```rust
pub trait PostProcessingSetup: Send {
    type InitialStage;
    type Worker: PostProcessingStep<InitialStage = Self::InitialStage>;
    type SetupArgs;

    fn setup(self, key: Key<Self::InitialStage>, args: Self::SetupArgs) -> Self::Worker;
}

pub trait PostProcessingStep: Send {
    type Result;
    type FinalStage;
    type InitialStage;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError>;
    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError>;
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError>;

    fn pipe<T>(
        self,
        other: T,
    ) -> impl PostProcessingStep<
        Result = <T::Worker as PostProcessingStep>::Result,
        FinalStage = <T::Worker as PostProcessingStep>::FinalStage,
        InitialStage = Self::InitialStage,
    >
    where
        Self: Sized,
        T: PostProcessingSetup<InitialStage = Self::FinalStage>,
        T::SetupArgs: From<Self::Result>,
    {
        Pipe::new(self, other)
    }
}
```

The `PostProcessingSetup` trait is implemented by structures that configure or
instantiate a particular step in the pipeline.
It defines the associated type InitialStage, that is the key state consumed by
the step, the concrete Worker type which performs the actual work and implements
`PostProcessingStep`, and `SetupArgs` which are auxiliary parameters needed to
create the worker and are typically either set at configuration time or are the
result of another PostProcessingStep.
The setup method consumes a Key<Self::InitialStage> together with these
arguments and returns the step instance.
The PostProcessingStep trait defines the runtime behaviour of a post-processing
stage.
A step is parameterized by:

- `InitialStage` the key state it operates on;
- `FinalStage` the key state produced once the step is complete;
- `Result` any intermediate data produced after completion (for example, BER
  estimates or reconciliation metadata).

Each step implements three core methods:

- `step()` performs one iteration of the protocol.
  It returns a `PPStep<Result, FollowerRequests>` which may either signal a
  completed iteration (`PPStep::Result`) or a request to the follower
  (`PPStep::GetUpdate`) containing a `FollowerRequests` message that the leader
  must send across the network.
- `update` (update: FollowerResponse) processes the follower’s reply,
  integrating it into the step’s internal state.
  This is called on the leader side whenever a corresponding FollowerResponse
  message is received from the peer.
- `finalize()` completes the step and outputs a new `Key<Self::FinalStage>`
  representing the updated key state ready for the next stage in the pipeline.

The `pipe()` method is a combinator that composes two post-processing stages and
is provided by the crate.
It returns a new `PostProcessingStep` implementation that chains the first and
second stages, automatically forwarding the final key and intermediate results
from one stage to the next.
This mechanism underpins the pipeline assembly visible in the module crate,
where components such as BER estimation, reconciliation, and privacy
amplification are composed into a single type-safe sequence.
Conceptually, these traits allow each algorithmic stage to be treated as a
self-contained worker that knows how to perform its local computation, handle
information received from the follower and produce a new key state.
At runtime, the leader executes this interface in a loop: calling `step()`
generates a `FollowerRequests` variant which is serialized and transmitted to
the follower.
The follower performs the requested operation and replies with a
`FollowerResponse`, which is passed in `toupdate()` on the leader side. This
continues until `step()` returns a terminal result, after which `finalize()`
produces the next-stage key.
In this way, the traits define a uniform, strongly-typed protocol boundary
between algorithmic logic and the communication subsystem.
Each post-processing algorithm implements these traits once, and the pipeline
infrastructure in the module crate handles orchestration, message transport, and
sequencing entirely generically.

## Application

The module crate implements the runtime node that executes the post-processing
pipeline.
It handles role assignment, classical communication, and key processing.
The directory structure is:

```
app/src
├── cli.rs
├── communication/
│   ├── handshake.rs
│   ├── key_processing.rs
│   ├── parse.rs
│   └── quic.rs
├── models/
│   ├── ber_estimation.rs
│   ├── peer.rs
│   ├── privacy_amplification.rs
│   └── update_qkd.rs
└── subsystems/
    └── role/
        ├── leader.rs
        └── follower.rs
```

### Communication layer

Classical communication is implemented using the QUIC protocol through the quinn
crate as shown below.

```rust
use quinn::{Endpoint, ServerConfig, ClientConfig};
use std::sync::Arc;

// QUIC endpoint setup for leader or follower
pub async fn setup_quic_endpoint -> Result<Endpoint> {
    if is_server {
        let mut server_config = ServerConfig::default();
        let (endpoint, _) = Endpoint::server(server_config, addr.parse()?)?;
        Ok(endpoint)
    } else {
        let client_config = ClientConfig::default();
        let endpoint = Endpoint::client(addr.parse()?)?;
        endpoint.set_default_client_config(Arc::new(client_config));
        Ok(endpoint)
    }
}

// Each new key uses a new stream between Leader and Follower
pub async fn open_key_stream(endpoint: &Endpoint) -> anyhow::Result<quinn::SendStream> {
    let connection = endpoint.connect(&"127.0.0.1:4433".parse()?, "qkd")?.await?;
    let send = connection.open_uni().await?;
    Ok(send)
}

// ...
```

Each sifted key triggers the creation of a new QUIC stream, maintaining
separation between parallel keys.
QUIC’s built-in encryption and multiplexing provide confidentiality and avoid
head-of-line blocking.

### Error correction

#### Cascade

The primary type driving the algorithm is Cascade shown below.
The Cascade worker implements PostProcessingStep and follows the
`step`/`update`/`finalize` pattern used throughout the pipeline.
The leader-side `step()` prepares a `FollowerRequests::Syndrome` request with
parity-block index lists, the follower computes and returns the parity bits in
`FollowerResponse::Syndrome`, and the leader’s `update()` uses those parities to
locate and correct errors via binary subdivision and advances iteration state.
After all passes, `finalize()` produces the reconciled key.

```rust
impl PostProcessingStep for Cascade {
type InitialStage = Reconciling;
type FinalStage = Reconciled;
type Result = ();

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        if self.parity_blocks.is_some() {
            return Err(PPError::new("Cannot process, outstanding parities missing"));
        }
        let blocks = loop {
            let blocks = self.iterations[self.iteration].get_unknown_parity_blocks();
            if !blocks.is_empty() {
                self.state.leak();
                break blocks;
            };
            // ... (iterate state transition logic, forward/backward passes, etc.)
        };

        // convert CascadeNode blocks into index vectors for the follower
        let blocks = self.parity_blocks.insert(blocks);
        let mut syndrome_indices = Vec::new();
        for block in blocks {
            syndrome_indices.push(block.read().unwrap().indicies.clone());
        }

        Ok(PPStep::GetUpdate(FollowerRequests::Syndrome(
            syndrome_indices,
        )))
    }

    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError> {
        match (update, self.parity_blocks.take()) {
            (_, None) => Err(PPError::new("Not expecting updates")),
            (FollowerResponse::Syndrome(syndromes), Some(blocks))
                if syndromes.len() == blocks.len() =>
            {
                self.leaked_bits += syndromes.len();
                let bool_vec: Vec<bool> = syndromes.iter().by_vals().collect();
                set_block_parities(&blocks, &bool_vec);
                Ok(())
            }
            (FollowerResponse::Syndrome(_), Some(_)) => {
                Err(PPError::new("Unexpected length of syndrome"))
            }
            _ => Err(PPError::new("Unexpected response")),
        }
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        let x = &self.iterations[0];
        let fixed = x.unshuffled_key.write().unwrap().clone();
        Ok(self.key.reconcile(fixed.into(), self.leaked_bits))
    }
}
```

#### Binary LDPC

The LDPC crate provides a one-way reconciliation method using parity-check
matrices.
This is typically a very sparse matrix so instead of a naive dense vector the
matrix is represented in the struct presented in the code snippet below.
The choice of `BTreeMap<usize, Neighbours>` rather than a plain `Vec` preserves
stable ordering and allows sparse indexing while still enabling ordered
iteration.

```rust
type Neighbours = Vec<usize>;

#[derive(Debug)]
pub struct ParityMatrix {
factors: BTreeMap<usize, Neighbours>,
variables: BTreeMap<usize, Neighbours>,
num_factors: usize,
num_variables: usize,
}
```

The syndrome is transmitted from the Follower to the Leader, who uses an
iterative decoding algorithm to reconstruct a consistent key.
The crate exposes these routines as part of a PostProcessingStep implementation
compatible with the core pipeline.
The decoder implements the classical sum-product belief propagation algorithm in
the log domain, iterating alternating variable to check and check to variable
message updates until either all parity checks are satisfied as calculated by
the `calculate_syndrome` function shown below, or a configured maximum number of
iterations is reached.

```rust
// impl of PartiyMatrix
fn calculate_syndrome(&self, message: &BitSlice) -> BitVec {
    let mut syndrome = bitvec![0; self.num_factors()];

    for (factor, neighbours) in self.iter_factors() {
        syndrome.set(
            *factor,
            neighbours
                .iter()
                .map(|&idx| message[idx])
                .collect::<BitVec>()
                .count_ones()
                % 2
                == 1,
        );
    }

    syndrome
}
```

Messages are stored as floating-point LLR values in sparse matrix structures
aligned with the Tanner graph of the underlying LDPC code as shown in the code
snippet below.

```rust
for iter in 0..max_iter {
    let tanhm = variable_to_factor.apply(|x| (x * 0.5).tanh());
    let tanhm*product = tanhm
        .iter_row()
        .map(|row| {
            row.values()
                .map(|v| if v.is_normal() { \_v } else { 1.0 })
                .product::<f64>()
        })
        .collect::<Vec<f64>>();

    for (i, row) in factor_to_variable.iter_row_mut().enumerate() {
        for (j, message) in row.iter_mut() {
            let product = tanhm_product[j];
            let mut divisor = tanhm[j][i];
            divisor = if divisor.is_normal() { divisor } else { 1.0 };
            let sign = if syndrome[j] { -1.0 } else { 1.0 };
            *message = sign * 2.0 * (product / divisor).atanh()
        }
    }

    for (variable, row) in factor_to_variable.iter_row().enumerate() {
        current_llr[variable] = row.values().sum::<f64>() + initial_llr[variable];
    }
    for (idx, l) in current_llr.iter().enumerate() {
        current_estimate.set(idx, l.is_sign_negative());
    }
    //...
}
```

The `current_estimate` variable holds the maximum likelihood estimate of the
corrected bits as of the current iteration and if the syndrome agrees with the
syndrome received from the follower then the decoder returns successfully.

#### Non-binary LDPC

Low-Density Parity-Check (LDPC) codes form the basis of one-way error correction
in many QKD post-processing systems.
The implementation in this stack extends the traditional binary formulation to a
non-binary LDPC scheme, enabling operation over Galois Fields of order ( 2^m ).
This allows each symbol to represent multiple bits, improving efficiency at low
error rates and enabling more flexible code design.
The non-binary LDPC implementation is organized as a self-contained crate that
provides encoding, syndrome computation, and iterative decoding routines.
It adheres to the same Process trait interface as the other reconciliation
modules so that it can be used interchangeably within the post-processing
pipeline.
The following excerpt from ldpc/src/lib.rs shows the syndrome computation, which
multiplies the parity-check matrix ( H ) by the received codeword vector ( x )
in the appropriate Galois Field:

```rust
use crate::gf::GFElement;

/// Compute the syndrome H * key over GF(2^m)
pub fn compute_syndrome(h_matrix: &[Vec<GFElement>], key: &[GFElement]) -> Vec<GFElement> {
    let mut syndrome = vec![GFElement::zero(); h_matrix.len()];

    for (i, row) in h_matrix.iter().enumerate() {
        let mut acc = GFElement::zero();

        for (j, val) in row.iter().enumerate() {
            acc += *val \* key[j]; // Addition and multiplication in GF(2^m)
        }

        syndrome[i] = acc;
    }
    syndrome
}
```

Here, the GFElement type encapsulates finite-field arithmetic, supporting
modular addition and multiplication according to the irreducible polynomial
defining the field.
A simplified version of its definition is:

```rust
#[derive(Clone, Copy, Debug)]
pub struct GFElement(pub u8, pub u8); // (value, field order)

impl GFElement {
    pub fn zero() -> Self { GFElement(0, 8) }
    pub fn one() -> Self { GFElement(1, 8) }
}

// Field operations
use std::ops::{Add, Mul};
impl Add for GFElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        GFElement(self.0 ^ other.0, self.1)
    }
}

impl Mul for GFElement {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        // Multiply in GF(2^m) using log/antilog tables
        GFElement(gf_mul(self.0, other.0, self.1), self.1)
    }
}
```

During decoding, the algorithm uses belief propagation extended to non-binary
fields, updating variable and check node messages as probability distributions
over $GF(2^m)$.
This approach reduces the number of communication rounds compared to interactive
methods like Cascade, making it suitable for high-throughput QKD systems.
The use of non-binary symbols improves performance on channels with higher noise
variance or when key material is represented in symbol groups larger than one
bit.
The code is structured to allow future acceleration through SIMD or GPU backends
without altering the high-level PostProcessingStep interface.

### Pipeline assembly and executiion

The module crate builds the runtime pipeline inside a create_pipeline function and drives it from an asynchronous loop that repeatedly executes the pipeline’s step() method.
The module composes concrete setup objects into a typed PostProcessingStep
pipeline, runs each pipeline step() in a blocking task as step() may perform
CPU-bound work, sends any FollowerRequests returned by to the follower, receives
the corresponding FollowerResponse, and passes that reply back into the pipeline
via update().
When the pipeline completes, finalize() is invoked to obtain the final key.
A literal example of a function implementing a complete pipeline with cascade
error correction would be:

```rust
fn create_pipeline(
key: Key<Reconciling>,
) -> Box<impl PostProcessingStep<InitialStage = Reconciling, FinalStage = Secret, Result = ()>> {
    let pipeline = BEREstimation::new(key, 0.05, 0.95)
        .pipe(SetupBerLimit::new(0.09))
        .pipe(SetupCascade::new(4))
        .pipe(SetupPrivacyAmplification);

    Box::new(pipeline)
}
```

The result is boxed as `Box<impl PostProcessingStep<...>>`, so it can be stored
and driven at runtime.
Note that the pipeline’s InitialStage is Reconciling and its FinalStage is
secret.
The execution a single step is done asynchronously as illustrated below.

```rust
async fn run_step<P>(
mut pipeline: Box<P>,
) -> Option<(
    Box<P>,
    Result<PPStep<<P as PostProcessingStep>::Result, FollowerRequests>, PPError>,
)>
where
    P: PostProcessingStep + 'static,
    <P as PostProcessingStep>::Result: Send,
{
    tokio::task::spawn_blocking(move || {
        let r = pipeline.step();
        (pipeline, r)
    })
    .await
    .ok()
}
```

run_step offloads the call to pipeline.step() to tokio::task::spawn_blocking. This pattern is used because step() may perform computation that should not block the async executor. run_step returns the pipeline, possibly updated/moved, together with the result produced by step(). This ensures that the internal state in pipeline is always correctly update even as the execution is moved between different threads as shown in lst. 10
Listing 10: Module Key Processing

```rust
async fn process_key(connection: Connection, key: Key<Sifted>) {
// wrap connection in helper that provides send/receive over QUIC streams
let stream = &mut QuinnStream::connect(connection).await.unwrap();
// buffer for classical communication
let mut buff = vec![0u8; 1024 * 1024];

    // register key and verify a key with the same ID and size exists on the follower

    // prepare pipeline: verify and move to Reconciling state
    let mut cur_pipeline = create_pipeline(key.verify().start_reconciliation());

    loop {
        // Execute one pipeline.step() in blocking worker and regain ownership of pipeline
        let maybe = run_step(cur_pipeline).await;
        let (pipeline, next_step) = match maybe {
            Some(t) => t,
            None => {
                // error joining the blocking task
                warn!("Error joining tokio task when running step");
                return;
            }
        };
        // restore pipeline ownership
        cur_pipeline = pipeline;

        match next_step {
            Ok(PPStep::Result(_)) => {
                // pipeline finished successfully
                info!("Finished reconciling");
                break;
            }

            Ok(PPStep::GetUpdate(request)) => {
                // send the request (FollowerRequests) to the follower
                if let Err(e) = send_message(stream, &request).await {
                    warn!("Unable to send request to peer: {:?}", e);
                    return;
                }

                // wait for follower reply (FollowerResponse)
                let update: FollowerResponse = match read_message(stream, &mut buff).await {
                    Ok(reply) => reply,
                    Err(e) => {
                        warn!("Unable to parse response: {:?}", e);
                        return;
                    }
                };

                // pass reply into pipeline to update internal state
                if let Err(e) = cur_pipeline.update(update) {
                    warn!("Error while processing response: {}", e);
                    return;
                }
            }

            Ok(PPStep::Abort) => {
                // pipeline requested abort
                info!("Aborting further post processing");
                return;
            }

            Err(e) => {
                // pipeline reported an error
                warn!("Error while running pipeline step: {}", e);
                return;
            }
        }
    }

    // finalize pipeline and obtain final key (Key<Secret>)
    match cur_pipeline.finalize() {
        Ok(final_key) => {
            // persist or hand off the final key (omitted for brevity)
            // e.g. write key to file / key store / notify system
            // ...
            info!("Key reconciled: {}", final_key.key_id());
        }
        Err(e) => {
            warn!("Error finalizing pipeline: {}", e);
        }
    }
}
```

## Contact us

If you would like to point out some bug or have some other comment
please feel free to contact us on [info@merqury.eu](mailto:info@merqury.eu).

## License

This project is licensed under the [PolyForm Noncommercial License
1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) that prohibits
commercial use of this product.
If you would like to use this product in a commercial environment, kindly
contact us on [info@merqury.eu](mailto:info@merqury.eu).
