# Autonomi Documentation

Welcome to the Autonomi documentation… these guides will help you get started building with the Autonomi Network.

## What is Autonomi?

Autonomi is a decentralised data and communications platform designed to provide complete privacy, security, and freedom by distributing data across a peer-to-peer network, rather than relying on centralised servers. Through end-to-end encryption, self-authentication, and the allocation of storage and bandwidth from users’ own devices, it seeks to create an autonomous, self-sustaining system where data ownership remains firmly in the hands of individuals rather than corporations.

## Quick Links

* [Installation Guide](getting-started/installation.md)
* Core Concepts:
  * [Data Types](core-concepts/data_types.md) - Understanding the fundamental data structures
  * [Client Modes](core-concepts/client_modes.md) - Different operational modes of the client
  * [Data Storage](core-concepts/data_storage.md) - How data is stored and retrieved
  * [Local Network Setup](how-to-guides/local_network.md) - Setting up a local development environment

### API References

* [Autonomi Client](api-reference/autonomi-client/) - Core client library for network operations
* [Ant Node](api-reference/ant-node/) - Node implementation for network participation
* [BLS Threshold Crypto](api-reference/blsttc.md) - Threshold cryptography implementation
* [Self Encryption](api-reference/self-encryption.md) - Content-based encryption library
* Low-level [Rust Crate API Reference](https://docs.rs/autonomi/latest/autonomi/)

## Language Support

Autonomi provides client libraries for multiple languages:

{% tabs %}
{% tab title="Rust" %}
```rust
use autonomi::Client;

let client = Client::new()?;
```
{% endtab %}

{% tab title="Python" %}
```python
from autonomi import Client

client = Client()
await client.connect()
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
import { Client } from 'autonomi';

const client = new Client();
await client.connect();
```
{% endtab %}
{% endtabs %}

## Building from Source

{% tabs %}
{% tab title="Rust" %}
```rust
# Clone the repository
git clone <https://github.com/maidsafe/autonomi.git>
cd autonomi

# Build the project
cargo build --release

# Run tests
cargo test --all-features

# Install locally
cargo install --path .
```
{% endtab %}

{% tab title="Python (using Maturin & uv)" %}
```python
# Install build dependencies
curl -LsSf <https://astral.sh/uv/install.sh> | sh
uv pip install maturin

# Clone the repository
git clone https://github.com/maidsafe/autonomi.git
cd autonomi

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # Unix
# or
.venv\Scripts\activate     # Windows

# Build and install the package
cd python
maturin develop

# Install dependencies
uv pip install -r requirements.txt
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
# Install build dependencies
npm install -g node-gyp

# Clone the repository
git clone https://github.com/maidsafe/autonomi.git
cd autonomi

# Build the Node.js bindings
cd nodejs
npm install
npm run build

# Link for local development
npm link
```
{% endtab %}
{% endtabs %}

## Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

For more details, see our [Contributing Guide](https://github.com/dirvine/autonomi/blob/main/CONTRIBUTING.md).

## Getting Help

* [GitHub Issues](https://github.com/dirvine/autonomi/issues)
