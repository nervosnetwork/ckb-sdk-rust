# refrence about molecule:
Read the documentation about [molecule](https://github.com/nervosnetwork/molecule).

# how to compile a mol file:
1. Make all dependencies available, like copy the system protocol file `blockchain.mol` into the working directory.
2. Run the compile command at the mol directory, replace the file names accordingly:
```bash
moleculec --language rust --schema-file omni_lock.mol | rustfmt > omni_lock.rs
```
3. Copy the file to the working directory.
4. Use the following lines:
```rust
#![allow(unused_imports)]
use ckb_types::molecule;
use ckb_types::packed::*;
use ckb_types::prelude::*;
```
to replace the existing lines:
```rust
use super::blockchain::*;
use molecule::prelude::*;
```
5. Add the following lines to the mod.rs file
```rust
#[allow(clippy::all)]
pub mod omni_lock;
```