# New Changelog Entry

@CHANGELOG.md

I want you to generate a changelog entry for a new release. The entry should have `$1` as the date.

You need to consider the code changes between now and the last stable release. These can be obtained
by getting the list of changes between now and the `$2` tag.

The entry can have the following categories:

* API
* Language Bindings
* Network
* Antctl
* Payments
* Client
* Launchpad

Then within each category, we are interested in what has been added, changed, fixed or removed. To
clarify the difference between a fix and a change, a fix is generally for a bug that was explicitly
identified and fixed, whereas a change was most likely done intentionally as part of some feature
request. If a change can be determined to be a breaking change with respect to Semantic Versioning,
this should be denoted by adding the text `[BREAKING]` to the end of the line.

When you build the added/changed/fixed/removed lists, for each item in the list, use a full stop,
even if it only has a single sentence. This accommodates items that need multiple sentences and
keeps the list consistently styled.

## Categories

Use the following guides to determine which category a change belongs to.

### API

The `API` category relates to the `autonomi` and `autonomi-core` crates. Here we are interested in
letting developers know about changes to the public interfaces for the API, down to the level of
function definitions, so this can be quite a detailed, fine-grained list of changes.

### Language Bindings

This category is for the language bindings we have for Python and NodeJS. Here we are again
interested in letting developers know about what new bindings are available or what has changed in
existing bindings. As per the API, an itemised list will be useful here.

For the other categories that follow, we are generally interested in higher-level descriptions
of changes.

### Network

This category relates to changes in these crates:
* `ant-bootstrap`
* `ant-protocol`
* `ant-node`
* `ant-metrics`

The `ant-node` crate produces a binary called `antnode`. Sometimes we will be interested in things
like changes to the commands or arguments for the binary, but most of the time we want to know about
changes in the operations or protocols in the network.

The `ant-bootstrap` crate has changes that can apply to both the network and the client, since both
use the bootstrapping mechanisms.

If there have been any metrics added or removed, use a sub list to describe each of those.

### Antctl

This category relates to changes in these crates:
* `ant-service-management`
* `ant-node-manager`

The `ant-node-manager` crate produces a binary called `antctl`. We are mostly want to inform users
about changes to this binary at the level of commands.

### Payments

This category relates to changes in these crates:
* `ant-evm`
* `evmlib`
* `evm-testnet`

We would mostly be interested in changes to `ant-evm` or `evmlib`. The `evm-testnet` crate produces
a binary that is used in local development, so there we would like to alert developers to any
changes in that binary interface that could affect their development setup.

### Ant Client

The client concerns the `ant-cli` crate, which produces the `ant` binary. Here we would be
interested in listing changes affecting any commands, or new commands that have been introduced. The
affected command should be called out by name, then the change should be described.

Changes in the `ant-bootstrap` crate can also be considered for the client, since the client uses
the same bootstrapping mechanisms as the `antnode` binary.

### Launchpad

The `node-launchpad` crate also builds a binary of the same name. This is a TUI binary, so generally
we will just be interested in changes to the terminal interface, but the binary also has a CLI. In
the rare cases where the CLI has changed, we would want those to be listed in a similar fashion as
per the client.
