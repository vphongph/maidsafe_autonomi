"""
Example demonstrating the use of pointers in the Autonomi network.
Pointers allow for creating references to data that can be updated.
"""

from autonomi_client import Client, Wallet, PaymentOption, PublicKey, SecretKey, PointerTarget, ChunkAddress

def main():
    # Initialize a wallet with a private key
    # This should be a valid Ethereum private key (64 hex chars without '0x' prefix)
    private_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    wallet = Wallet(private_key)
    print(f"Wallet address: {wallet.address()}")
    print(f"Wallet balance: {wallet.balance()}")

    # Connect to the network
    peers = [
        "/ip4/127.0.0.1/tcp/12000",
        "/ip4/127.0.0.1/tcp/12001"
    ]
    client = Client.connect(peers)

    # First, let's upload some data that we want to point to
    target_data = b"Hello, I'm the target data!"
    target_addr = client.data_put_public(target_data, PaymentOption.wallet(wallet))
    print(f"Target data uploaded to: {target_addr}")

    # Create a pointer target from the address
    chunk_addr = ChunkAddress.from_hex(target_addr)
    target = PointerTarget.from_chunk_address(chunk_addr)
    
    # Create owner key pair
    owner_key = SecretKey.new()
    owner_pub = PublicKey.from_secret_key(owner_key)
    
    # Create and store the pointer
    counter = 0  # Start with counter 0
    client.pointer_put(owner_pub, counter, target, owner_key, wallet)
    print(f"Pointer stored successfully")

    # Calculate the pointer address
    pointer_addr = client.pointer_address(owner_pub, counter)
    print(f"Pointer address: {pointer_addr}")

    # Later, we can retrieve the pointer
    pointer = client.pointer_get(pointer_addr)
    print(f"Retrieved pointer target: {pointer.target().hex()}")

    # We can then use the target address to get the original data
    retrieved_data = client.data_get_public(pointer.target().hex())
    print(f"Retrieved target data: {retrieved_data.decode()}")

if __name__ == "__main__":
    main()
