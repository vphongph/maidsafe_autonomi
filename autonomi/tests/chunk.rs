// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_logging::LogBuilder;
use autonomi::client::payment::PaymentOption;
use autonomi::{client::chunk::Chunk, Bytes, Client};
use eyre::Result;
use serial_test::serial;
use test_utils::evm::get_funded_wallet;

#[tokio::test]
#[serial]
async fn chunk_put_manual() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("chunk", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();

    let chunk = Chunk::new(Bytes::from("Hello, world!"));

    // estimate the cost of the chunk
    let cost = client.chunk_cost(chunk.address()).await?;
    println!("chunk cost: {cost}");

    // put the chunk
    let payment_option = PaymentOption::from(&wallet);
    let (cost, addr) = client.chunk_put(&chunk, payment_option).await?;
    assert_eq!(addr, *chunk.address());
    println!("chunk put 1 cost: {cost}");

    // wait for the chunk to be replicated
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // check that the chunk is stored
    let got = client.chunk_get(&addr).await?;
    assert_eq!(got, chunk.clone());
    println!("chunk got 1");

    Ok(())
}
