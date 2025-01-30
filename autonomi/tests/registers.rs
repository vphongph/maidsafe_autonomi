// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_logging::LogBuilder;
use autonomi::{
    client::{
        payment::PaymentOption,
        register::{RegisterAddress, RegisterValue},
    },
    graph::GraphError,
    register::RegisterError,
    Client,
};
use eyre::Result;
use serial_test::serial;
use test_utils::evm::get_funded_wallet;

#[tokio::test]
#[serial]
async fn registers_usage() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("registers", false);
    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let main_key = bls::SecretKey::random();

    let register_key = Client::register_key_from_name(&main_key, "register1");
    let mut content: RegisterValue = [0; 32];
    content[..13].copy_from_slice(b"Hello, World!");
    let cost = client.register_cost(&register_key.public_key()).await?;
    println!("register cost: {cost}");

    // create the register
    let (cost, addr) = client
        .register_create(
            &register_key,
            content,
            PaymentOption::from(&wallet),
            PaymentOption::from(&wallet),
        )
        .await?;
    println!("register created: {cost} {addr:?}");
    assert_eq!(addr, RegisterAddress::new(register_key.public_key()));

    // wait for the register to be replicated
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // get the register
    let value = client.register_get(&addr).await?;
    assert_eq!(value, content);

    // update the register
    let mut new_content: RegisterValue = [0; 32];
    new_content[..26].copy_from_slice(b"any 32 bytes of fresh data");
    let cost = client
        .register_update(&register_key, new_content, PaymentOption::from(&wallet))
        .await?;
    println!("register updated: {cost}");

    // wait for the register to be replicated
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // get the register again
    let value = client.register_get(&addr).await?;
    assert_eq!(value, new_content);

    Ok(())
}

#[tokio::test]
#[serial]
async fn registers_errors() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("registers2", false);
    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let main_key = bls::SecretKey::random();

    let register_key = Client::register_key_from_name(&main_key, "register1");
    let mut content: RegisterValue = [0; 32];
    content[..13].copy_from_slice(b"Hello, World!");
    let cost = client.register_cost(&register_key.public_key()).await?;
    println!("register cost: {cost}");

    // try to update non existing register
    let res = client
        .register_update(&register_key, content, PaymentOption::from(&wallet))
        .await;
    println!("register update without creating should fail: {res:?}");
    assert!(matches!(
        res.unwrap_err(),
        RegisterError::CannotUpdateNewRegister
    ));

    // create the register
    let (cost, addr) = client
        .register_create(
            &register_key,
            content,
            PaymentOption::from(&wallet),
            PaymentOption::from(&wallet),
        )
        .await?;
    println!("register created: {cost} {addr:?}");
    assert_eq!(addr, RegisterAddress::new(register_key.public_key()));

    // wait for the register to be replicated
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // try to create the register again
    let res = client
        .register_create(
            &register_key,
            content,
            PaymentOption::from(&wallet),
            PaymentOption::from(&wallet),
        )
        .await;
    println!("register create second time should fail: {res:?}");
    assert!(matches!(
        res.unwrap_err(),
        RegisterError::GraphError(GraphError::AlreadyExists(_))
    ));

    Ok(())
}
