"""
Example demonstrating the use of pointers in the Autonomi network.
Pointers allow for creating references to data that can be updated.
"""

from autonomi_client import Client, Network, Wallet, PaymentOption, PublicKey, SecretKey, PointerTarget, ChunkAddress
import asyncio

async def main():
    # Initialize a wallet with a private key
    # This should be a valid Ethereum private key (64 hex chars)
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    network = Network(True)
    wallet = Wallet.new_from_private_key(network, private_key)
    print(f"Wallet address: {wallet.address()}")
    print(f"Wallet balance: {wallet.balance()}")

    # Connect to the network
    client = await Client.init_local()

    # First, let's upload some data that we want to point to
    target_data = b"Hello, I'm the target data!"
    target_addr = await client.data_put_public(target_data, PaymentOption.wallet(wallet))
    print(f"Target data uploaded to: {target_addr}")

    # Create a pointer target from the address
    chunk_addr = ChunkAddress.from_chunk_address(target_addr)
    target = PointerTarget.from_chunk_address(chunk_addr)
    
    # Create owner key pair
    owner_key = SecretKey()
    owner_pub = owner_key.public_key()
    
    # Create and store the pointer
    counter = 0  # Start with counter 0
    await client.pointer_put(owner_pub, counter, target, owner_key, wallet)
    print(f"Pointer stored successfully")

    # Calculate the pointer address
    pointer_addr = client.pointer_address(owner_pub, counter)
    print(f"Pointer address: {pointer_addr}")

    # Later, we can retrieve the pointer
    pointer = await client.pointer_get(pointer_addr)
    print(f"Retrieved pointer target: {pointer.target().hex()}")

    # We can then use the target address to get the original data
    retrieved_data = await client.data_get_public(pointer.target().hex())
    print(f"Retrieved target data: {retrieved_data.decode()}")


asyncio.run(main())
