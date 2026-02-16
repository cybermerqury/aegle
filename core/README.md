# PPaaS

## The traits

In order to specify your own post-processing pipeline the `ppaas_core` library
provides the following traits:

- `PostProcessingStep`
- `PostProcessingSetup`

## Post Processing Step

This trait exposes two methods:

```rust
    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError>;
    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError>;
```

The intended usecase for a post processing step is to be used in a looping fashion, and also a method:

```rust
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError>;
```

Which consumes the step, preventing further processing, and outputs the resulting key.

The typical usage would look something like

```rust
// pp_step is a struct that implements PostProcessingStep
let step_result = loop {
    match pp_step.step()? {
        PPStep::Result(result) => {
            // pp_step can be finalized
            break result
        },
        PPStep::GetUpdate(update) => {
            //update is of type FollowerRequest
            send_request(update)
            let response: FollowerResponse = get_reponse()
            pp_step.update(response)?
        }
        PPStep::Abort => {
            // Post processing step has decided to abort
            send_abort_request_to_follower()
        }
    }
    // maybe do something with step_result
    let key = pp_step.finalize()
}
```

## Setting up a pipeline

The code allows combining of `PostProcessingStep`s together, creating a new `PostProcessingStep`. This occurs through the `PostProcessingSetup` trait which acts as a factory of `PostProcessingStep`

```rust
pub trait PostProcessingSetup {
    type InitialStage;
    type Worker: PostProcessingStep<InitialStage = Self::InitialStage>;
    type SetupArgs;
    fn setup(self, key: Key<Self::InitialStage>, args: Self::SetupArgs) -> Self::Worker;
}
```

Given a struct implementing `PostProcessingStep` and another struct implementing `PostProcessingSetup`, the two can be combined

```rust
let c = a.pipe(b)
// c is now a struct implementing PostProcessingStep
```

The pipe method handles conversion of the result of `a` into the type of `b`'s `SetupArgs`

And example pipeline might look something like

```rust
let pipeline = ber_estimate
                    .pipe(setup_ber_limit)
                    .pipe(setup_error_correction)
                    .pipe(setup_privacy_amplification)

```

then by performing the looping operation with `pipeline.step()` we step through all the seperate stages of post processing, the results of the previous stages informing the creation of subsequent stages: eg if the ber estimate is too high the second step would cause further key processing to be aborted. The estimated error is also provided to the error_correction step, which can be used to select and set up the error correction algorithm to use, and so on.
