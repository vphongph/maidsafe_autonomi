use autonomi::{get_evm_network_from_env, local_evm_network_from_csv, Network};
use color_eyre::eyre::{Context, Result};

use std::sync::OnceLock;

static EVM_NETWORK: OnceLock<Network> = OnceLock::new();

pub(crate) fn get_evm_network(local: bool) -> Result<Network> {
    if let Some(network) = EVM_NETWORK.get() {
        return Ok(network.clone());
    }

    let res = match get_evm_network_from_env() {
        Ok(evm_network) => Ok(evm_network),
        Err(_) if local => {
            Ok(local_evm_network_from_csv().wrap_err("Failed to get local EVM network")?)
        }
        Err(_) => Ok(Default::default()),
    };

    if let Ok(network) = res.as_ref() {
        let _ = EVM_NETWORK.set(network.clone());
    }

    res
}
