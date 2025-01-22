# Error Handling Reference

This page documents the error types and handling patterns for the Autonomi Client API.

## Error Types

### ChunkError

Errors related to chunk operations.

{% tabs %}
{% tab title="Rust" %}
```rust
pub enum ChunkError {
    NotFound,
    InvalidSize,
    NetworkError(NetworkError),
    StorageFull,
}

match client.get_chunk(address).await {
    Ok(chunk) => { /* Process chunk */ }
    Err(ChunkError::NotFound) => { /* Handle missing chunk */ }
    Err(ChunkError::NetworkError(e)) => { /* Handle network issues */ }
    Err(e) => { /* Handle other errors */ }
}
```
{% endtab %}

{% tab title="Python" %}
```python
class ChunkError(Exception):
    class NotFound(ChunkError): pass
    class InvalidSize(ChunkError): pass
    class NetworkError(ChunkError): pass
    class StorageFull(ChunkError): pass

try:
    chunk = client.get_chunk(address)
except ChunkError.NotFound:
    # Handle missing chunk
    pass
except ChunkError.NetworkError as e:
    # Handle network issues
    pass
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
class ChunkError extends Error {
    static NotFound: typeof ChunkError;
    static InvalidSize: typeof ChunkError;
    static NetworkError: typeof ChunkError;
    static StorageFull: typeof ChunkError;
}

try {
    const chunk = await client.getChunk(address);
} catch (error) {
    if (error instanceof ChunkError.NotFound) {
        // Handle missing chunk
    } else if (error instanceof ChunkError.NetworkError) {
        // Handle network issues
    }
}
```
{% endtab %}
{% endtabs %}

### PointerError

Errors related to pointer operations.

{% tabs %}
{% tab title="Rust" %}
```rust
pub enum PointerError {
    NotFound,
    VersionConflict,
    InvalidTarget,
}

match client.update_pointer(address, new_target).await {
    Ok(_) => { /* Success */ }
    Err(PointerError::VersionConflict) => { /* Handle conflict */ }
    Err(e) => { /* Handle other errors */ }
}
```
{% endtab %}

{% tab title="Python" %}
```python
class PointerError(Exception):
    class NotFound(PointerError): pass
    class VersionConflict(PointerError): pass
    class InvalidTarget(PointerError): pass

try:
    client.update_pointer(address, new_target)
except PointerError.VersionConflict:
    # Handle version conflict
    pass
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
class PointerError extends Error {
    static NotFound: typeof PointerError;
    static VersionConflict: typeof PointerError;
    static InvalidTarget: typeof PointerError;
}

try {
    await client.updatePointer(address, newTarget);
} catch (error) {
    if (error instanceof PointerError.VersionConflict) {
        // Handle version conflict
    }
}
```
{% endtab %}
{% endtabs %}

## Error Handling Patterns

### Retry Logic

For transient errors like network issues:

{% tabs %}
{% tab title="Rust" %}
```rust
async fn update_pointer_safely(
    client: &Client,
    address: Address,
    new_target: Address
) -> Result<()> {
    loop {
        match client.update_pointer(address, new_target).await {
            Ok(_) => break Ok(()),
            Err(PointerError::VersionConflict) => {
                let current = client.resolve_pointer(address).await?;
                if current == new_target {
                    break Ok(());
                }
                continue;
            }
            Err(e) => break Err(e),
        }
    }
}
```
{% endtab %}

{% tab title="Python" %}
```python
async def update_pointer_safely(client, address, new_target):
    while True:
        try:
            await client.update_pointer(address, new_target)
            break
        except PointerError.VersionConflict:
            current = await client.resolve_pointer(address)
            if current == new_target:
                break
            continue
        except Exception as e:
            raise e
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
async function updatePointerSafely(
    client: Client,
    address: Address,
    newTarget: Address
): Promise<void> {
    while (true) {
        try {
            await client.updatePointer(address, newTarget);
            break;
        } catch (error) {
            if (error instanceof PointerError.VersionConflict) {
                const current = await client.resolvePointer(address);
                if (current.equals(newTarget)) break;
                continue;
            }
            throw error;
        }
    }
}
```
{% endtab %}
{% endtabs %}

### Error Recovery

For handling version conflicts in pointers:

{% tabs %}
{% tab title="Rust" %}
```rust
async fn update_pointer_safely(
    client: &Client,
    address: Address,
    new_target: Address
) -> Result<()> {
    loop {
        match client.update_pointer(address, new_target).await {
            Ok(_) => break Ok(()),
            Err(PointerError::VersionConflict) => {
                let current = client.resolve_pointer(address).await?;
                if current == new_target {
                    break Ok(());
                }
                continue;
            }
            Err(e) => break Err(e),
        }
    }
}
```
{% endtab %}

{% tab title="Python" %}
```python
async def update_pointer_safely(client, address, new_target):
    while True:
        try:
            await client.update_pointer(address, new_target)
            break
        except PointerError.VersionConflict:
            current = await client.resolve_pointer(address)
            if current == new_target:
                break
            continue
        except Exception as e:
            raise e
```
{% endtab %}

{% tab title="Node.js" %}
```typescript
async function updatePointerSafely(
    client: Client,
    address: Address,
    newTarget: Address
): Promise<void> {
    while (true) {
        try {
            await client.updatePointer(address, newTarget);
            break;
        } catch (error) {
            if (error instanceof PointerError.VersionConflict) {
                const current = await client.resolvePointer(address);
                if (current.equals(newTarget)) break;
                continue;
            }
            throw error;
        }
    }
}
```
{% endtab %}
{% endtabs %}
