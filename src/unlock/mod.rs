pub(crate) mod omni_lock;
pub mod rc_data;
mod signer;
mod unlocker;

pub use signer::{
    generate_message, AcpScriptSigner, ChequeAction, ChequeScriptSigner, MultisigConfig,
    OmniLockScriptSigner, OmniUnlockMode, ScriptSignError, ScriptSigner, SecpMultisigScriptSigner,
    SecpSighashScriptSigner,
};
pub use unlocker::{
    build_placeholder_witness, fill_witness_lock, reset_witness_lock, AcpUnlocker, ChequeUnlocker,
    OmniLockUnlocker, ScriptUnlocker, SecpMultisigUnlocker, SecpSighashUnlocker, UnlockError,
};

pub use omni_lock::{IdentityFlag, InfoCellData, OmniLockAcpConfig, OmniLockConfig};
