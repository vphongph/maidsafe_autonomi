---
description: >-
  This section will help you get started on your Autonomi adventure as quickly
  as possible. It will walk you through setting up your development environment
  and writing a simple Autonomi app.
---

# Quick Start Guide

## My first App

Let's get right to it and build your first Autonomi app!

### Add Autonomi as a Dependency

First import our Autonomi dependency using the language you love:

{% tabs %}
{% tab title="Rust" %}
```rust
cargo add autonomi
```
{% endtab %}

{% tab title="Python" %}

{% endtab %}
{% endtabs %}

### Setup a Client

To connect to the Autonomi network, we'll need a \`Client\`:

{% tabs %}
{% tab title="Rust" %}
```rust
use autonomi::Client;

#[tokio::main]
async fn main() {
    let client = Client::init().await.unwrap();
}
```
{% endtab %}

{% tab title="Python" %}

{% endtab %}
{% endtabs %}

### Download a Dog Picture

What better way is there to show off the capabilities of the network? Let's download a dog picture from this public DataAddress:

```
48a5524425873b21c77145a97ab64abb9ecba3ac4fee8a67f81272a5dcd912a1
```

{% tabs %}
{% tab title="Rust" %}
```rust
use autonomi::Client;

#[tokio::main]
async fn main() {
    let client = Client::init().await.unwrap();

    let data_address =
        DataAddr::from_content(b"48a5524425873b21c77145a97ab64abb9ecba3ac4fee8a67f81272a5dcd912a1");

    // Get the bytes of the dog picture
    let dog_picture = client.data_get_public(data_address).await.unwrap();

    println!("Data fetched: {:?}", dog_picture);
}
```
{% endtab %}

{% tab title="Python" %}

{% endtab %}
{% endtabs %}

.
