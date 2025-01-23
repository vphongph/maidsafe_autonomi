use ant_node::spawn::network::NetworkSpawner;
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env("RUST_LOG"))
        .init();

    let network_size = 20;

    let running_network = NetworkSpawner::new()
        .with_evm_network(Default::default())
        .with_local(true)
        .with_size(network_size)
        .spawn()
        .await
        .expect("Failed to spawn network");

    // Wait for nodes to dial each other
    sleep(Duration::from_secs(10)).await;

    for node in running_network.running_nodes() {
        println!("Node listening on: {:?}", node.get_listen_addrs().await);
    }

    running_network.shutdown();
}
