# Ant Node API Reference

The Ant Node provides a comprehensive API for running and managing nodes in the Autonomi network. This documentation covers both the Python bindings and the Rust implementation.

## Installation

\=== "Python" \`\`\`bash # Install using uv (recommended) curl -LsSf [https://astral.sh/uv/install.sh](https://astral.sh/uv/install.sh) | sh uv pip install maturin uv pip install antnode

````
# Or using pip
pip install antnode
```
````

\=== "Rust" `toml # Add to Cargo.toml [dependencies] ant-node = "0.3.2"`

## Basic Usage

\=== "Python" \`\`\`python from antnode import AntNode

````
# Create and start a node
node = AntNode()
node.run(
    rewards_address="0x1234567890123456789012345678901234567890",  # Your EVM wallet address
    evm_network="arbitrum_sepolia",  # or "arbitrum_one" for mainnet
    ip="0.0.0.0",
    port=12000,
    initial_peers=[
        "/ip4/142.93.37.4/udp/40184/quic-v1/p2p/12D3KooWPC8q7QGZsmuTtCYxZ2s3FPXPZcS8LVKkayXkVFkqDEQB",
    ],
    local=False,
    root_dir=None,  # Uses default directory
    home_network=False
)
```
````

\=== "Rust" \`\`\`rust use ant\_node::{NodeBuilder, NodeEvent}; use ant\_evm::RewardsAddress; use libp2p::Multiaddr;

````
// Create and start a node
let node = NodeBuilder::new()
    .rewards_address(rewards_address)
    .evm_network(evm_network)
    .ip(ip)
    .port(port)
    .initial_peers(initial_peers)
    .local(false)
    .root_dir(None)
    .home_network(false)
    .build()?;
```
````

## Core Features

### Node Information

\=== "Python" \`\`\`python # Get node's peer ID peer\_id = node.peer\_id()

````
# Get current rewards address
address = node.get_rewards_address()

# Get routing table information
kbuckets = node.get_kbuckets()
for distance, peers in kbuckets:
    print(f"Distance {distance}: {len(peers)} peers")

# Get all stored record addresses
records = node.get_all_record_addresses()
```
````

\=== "Rust" \`\`\`rust // Get node's peer ID let peer\_id = node.peer\_id();

````
// Get current rewards address
let address = node.rewards_address();

// Get routing table information
let kbuckets = node.get_kbuckets()?;
for (distance, peers) in kbuckets {
    println!("Distance {}: {} peers", distance, peers.len());
}

// Get all stored record addresses
let records = node.get_all_record_addresses()?;
```
````

### Storage Operations

\=== "Python" \`\`\`python # Store data key = "0123456789abcdef" # Hex string value = b"Hello, World!" node.store\_record(key, value, "chunk")

````
# Retrieve data
data = node.get_record(key)

# Delete data
success = node.delete_record(key)

# Get total storage size
size = node.get_stored_records_size()
```
````

\=== "Rust" \`\`\`rust use ant\_protocol::storage::ValidationType;

````
// Store data
let key = "0123456789abcdef";  // Hex string
let value = b"Hello, World!";
node.store_record(key, value, ValidationType::Chunk)?;

// Retrieve data
let data = node.get_record(key)?;

// Delete data
let success = node.delete_record(key)?;

// Get total storage size
let size = node.get_stored_records_size()?;
```
````

### Directory Management

\=== "Python" \`\`\`python # Get various directory paths root\_dir = node.get\_root\_dir() logs\_dir = node.get\_logs\_dir() data\_dir = node.get\_data\_dir()

````
# Get default directory for a specific peer
default_dir = AntNode.get_default_root_dir(peer_id)
```
````

\=== "Rust" \`\`\`rust // Get various directory paths let root\_dir = node.root\_dir(); let logs\_dir = node.logs\_dir(); let data\_dir = node.data\_dir();

````
// Get default directory for a specific peer
let default_dir = Node::get_default_root_dir(peer_id)?;
```
````

## Event Handling

\=== "Python" `python # Event handling is automatic in Python bindings # Events are logged and can be monitored through the logging system`

\=== "Rust" \`\`\`rust use ant\_node::{NodeEvent, NodeEventsReceiver};

````
// Get event receiver
let mut events: NodeEventsReceiver = node.event_receiver();

// Handle events
while let Ok(event) = events.recv().await {
    match event {
        NodeEvent::ConnectedToNetwork => println!("Connected to network"),
        NodeEvent::ChunkStored(addr) => println!("Chunk stored: {}", addr),
        NodeEvent::RewardReceived(amount, addr) => {
            println!("Reward received: {} at {}", amount, addr)
        }
        NodeEvent::ChannelClosed => break,
        NodeEvent::TerminateNode(reason) => {
            println!("Node terminated: {}", reason);
            break;
        }
    }
}
```
````

## Configuration Options

### Node Configuration

* `rewards_address`: EVM wallet address for receiving rewards
* `evm_network`: Network to use ("arbitrum\_sepolia" or "arbitrum\_one")
* `ip`: IP address to listen on
* `port`: Port to listen on
* `initial_peers`: List of initial peers to connect to
* `local`: Whether to run in local mode
* `root_dir`: Custom root directory path
* `home_network`: Whether the node is behind NAT

### Network Types

* `arbitrum_sepolia`: Test network
* `arbitrum_one`: Main network

## Error Handling

\=== "Python" `python try: node.store_record(key, value, "chunk") except Exception as e: print(f"Error storing record: {e}")`

\=== "Rust" \`\`\`rust use ant\_node::error::Error;

````
match node.store_record(key, value, ValidationType::Chunk) {
    Ok(_) => println!("Record stored successfully"),
    Err(Error::StorageFull) => println!("Storage is full"),
    Err(Error::InvalidKey) => println!("Invalid key format"),
    Err(e) => println!("Other error: {}", e),
}
```
````

## Best Practices

1. **Error Handling**
   * Always handle potential errors appropriately
   * Implement retry logic for network operations
   * Log errors for debugging
2. **Resource Management**
   * Monitor storage usage
   * Clean up unused records
   * Handle events promptly
3. **Network Operations**
   * Use appropriate timeouts
   * Handle network disconnections
   * Maintain peer connections
4. **Security**
   * Validate input data
   * Secure storage of keys
   * Regular backups of important data
