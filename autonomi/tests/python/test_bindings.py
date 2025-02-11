import pytest
from autonomi_client import (
    ChunkAddress,
    PointerTarget,
    Pointer,
    PointerAddress,
    SecretKey,
    PublicKey,
    Wallet
)

def test_chunk_address_creation():
    # Test creating a ChunkAddress from bytes
    test_data = b"test data for chunk address"
    chunk_addr = ChunkAddress(test_data)
    
    # Test hex representation
    hex_str = chunk_addr.hex
    assert isinstance(hex_str, str)
    assert len(hex_str) == 64  # 32 bytes = 64 hex chars
    
    # Test string representation
    str_repr = str(chunk_addr)
    assert str_repr == hex_str
    
    # Test repr
    repr_str = repr(chunk_addr)
    assert repr_str == f"ChunkAddress({hex_str})"

def test_chunk_address_from_hex():
    # Create a chunk address
    original = ChunkAddress(b"test data")
    hex_str = original.hex
    
    # Create new chunk address from hex
    recreated = ChunkAddress.from_chunk_address(hex_str)
    assert recreated.hex == hex_str

def test_pointer_target_with_chunk_address():
    # Create a chunk address
    chunk_addr = ChunkAddress(b"test data for pointer target")
    
    # Create pointer target from chunk address
    target = PointerTarget.from_chunk_address(chunk_addr)
    
    # Verify the hex matches
    assert isinstance(target.hex, str)
    assert len(target.hex) == 64

def test_pointer_creation():
    # Create necessary components
    owner = PublicKey()
    counter = 42
    chunk_addr = ChunkAddress(b"test data for pointer")
    target = PointerTarget.from_chunk_address(chunk_addr)
    key = SecretKey()
    
    # Create pointer
    pointer = Pointer(owner, counter, target, key)
    
    # Verify pointer properties
    assert isinstance(pointer.hex, str)
    assert len(pointer.hex) == 64
    
    # Test network address
    addr = pointer.network_address()
    assert isinstance(addr, PointerAddress)
    assert isinstance(addr.hex, str)
    assert len(addr.hex) == 64

def test_pointer_target_creation():
    # Test direct creation
    test_data = b"test data for pointer target"
    target = PointerTarget(test_data)
    
    # Verify hex
    assert isinstance(target.hex, str)
    assert len(target.hex) == 64
    
    # Test from_xorname
    target2 = PointerTarget.from_xorname(test_data)
    assert isinstance(target2.hex, str)
    assert len(target2.hex) == 64

def test_invalid_hex():
    # Test invalid hex string for chunk address
    with pytest.raises(ValueError):
        ChunkAddress.from_chunk_address("invalid hex")
    
    # Test invalid hex string for pointer address
    with pytest.raises(ValueError):
        PointerAddress("invalid hex") 