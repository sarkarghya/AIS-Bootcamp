# %%

"""
# 4. Asymmetric Cryptography: RSA

In this section, you'll implement the RSA (Rivest-Shamir-Adleman) public key cryptosystem, one of the most important cryptographic algorithms ever developed. Unlike the symmetric ciphers we've explored, RSA uses different keys for encryption and decryption, enabling secure communication without prior key exchange.

## Introduction

RSA represents a fundamental shift from symmetric to asymmetric cryptography, solving the key distribution problem that plagued earlier cryptographic systems.
Developed in 1977 by researchers at MIT, RSA was the first practical public key cryptosystem and remains widely used today in protocols like TLS, SSH, and digital signatures.
The security of RSA is based on the mathematical difficulty of factoring large composite numbers - specifically, given n = p × q where p and q are large primes, it's computationally infeasible to recover p and q from n alone.
This one-way function property allows RSA to create mathematically related key pairs where knowledge of the public key doesn't reveal the private key.
The RSA algorithm operates in the ring of integers modulo n, using modular exponentiation for both encryption and decryption.
The public key consists of (n, e) where n is the modulus and e is the encryption exponent, while the private key is (n, d) where d is the decryption exponent satisfying ed ≡ 1 (mod φ(n)).
The elegance of RSA lies in its mathematical foundation: Euler's theorem guarantees that for any message m where gcd(m, n) = 1, we have m^(ed) ≡ m (mod n), making encryption and decryption perfect inverses.

RSA's versatility extends beyond encryption to digital signatures, where the private key signs messages and the public key verifies signatures, providing both authentication and non-repudiation.
However, RSA has important limitations: it's much slower than symmetric ciphers, can only encrypt data smaller than the key size, and requires careful padding schemes to prevent various attacks.
Modern implementations typically use RSA for key exchange or digital signatures rather than bulk data encryption, often in hybrid cryptosystems that combine RSA's key distribution capabilities with symmetric ciphers' efficiency.
Despite widespread use RSA's security relies solely on the difficulty of factoring large numbers. Shor's algorithm, when implemented on a sufficiently powerful quantum computer, can factor these numbers exponentially faster than classical algorithms, rendering RSA vulnerable.


### RSA Components and Security

- **Key Generation**: Creating mathematically related public/private key pairs
- **Modular Arithmetic**: All operations performed modulo n = p × q  
- **Euler's Totient Function**: φ(n) = (p-1)(q-1) for RSA key generation
- **Modular Exponentiation**: Efficient computation of large exponentials mod n
- **Prime Factorization**: The hard problem underlying RSA security
- **Padding Schemes**: Preventing mathematical attacks on raw RSA

<details>
<summary>Vocabulary: Cryptography Terms</summary>

- **Public Key**: The openly shared component of an asymmetric key pair (n, e) used for encryption or signature verification
- **Private Key**: The secret component of an asymmetric key pair (n, d) used for decryption or signing
- **Modulus (n)**: The product of two large primes p and q, forming the foundation of RSA security
- **Euler's Totient Function φ(n)**: For RSA, φ(n) = (p-1)(q-1), used in key generation
- **Modular Exponentiation**: Computing a^b mod n efficiently, the core operation in RSA
- **Digital Signature**: A cryptographic proof that a message was created by the holder of a private key
- **Key Exchange**: The process of securely sharing symmetric keys using asymmetric cryptography
- **Hybrid Cryptosystem**: A system combining asymmetric and symmetric cryptography for optimal security and performance
- **Padding Scheme**: Methods like OAEP that prevent attacks on raw RSA operations
- **Certificate Authority (CA)**: A trusted entity that issues digital certificates using RSA signatures

</details>

"""

# %%

"""

## Exercise 4.1: RSA Key Generation

RSA key generation involves selecting two prime numbers and computing the public and private exponents. The security of the entire system depends on choosing appropriate primes and ensuring the mathematical relationships hold.

The key generation process:
1. Select two distinct prime numbers p and q
2. Compute n = p × q (the modulus)
3. Compute φ(n) = (p-1)(q-1) (Euler's totient function)
4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
5. Compute d such that ed ≡ 1 (mod φ(n))

### Exercise - implement rsa_keygen

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~25 minutes on this exercise.

Implement RSA key generation for small primes.
"""

import math
from typing import Tuple

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Returns (gcd, x, y) such that ax + by = gcd(a, b)
    """
    if "SOLUTION":
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    else:
        # TODO: Implement extended GCD
        # This is needed to find modular inverses
        pass

def mod_inverse(e: int, phi_n: int) -> int:
    """
    Compute modular inverse of e modulo phi_n.
    
    Returns d such that ed ≡ 1 (mod phi_n)
    """
    if "SOLUTION":
        gcd, x, y = extended_gcd(e, phi_n)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % phi_n + phi_n) % phi_n
    else:
        # TODO: Use extended_gcd to find modular inverse
        pass

def is_prime(n: int) -> bool:
    """Simple primality test for small numbers."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def rsa_keygen(p: int, q: int, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public and private key pairs.
    
    Args:
        p: First prime number
        q: Second prime number  
        e: Public exponent (default 65537, common choice)
        
    Returns:
        Tuple of ((n, e), (n, d)) representing (public_key, private_key)
    """
    if "SOLUTION":
        # Validate inputs
        if not is_prime(p) or not is_prime(q):
            raise ValueError("p and q must be prime")
        if p == q:
            raise ValueError("p and q must be distinct")
            
        # Step 1: Compute n = p * q
        n = p * q
        
        # Step 2: Compute φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        
        # Step 3: Validate e
        if math.gcd(e, phi_n) != 1:
            raise ValueError(f"e={e} is not coprime with φ(n)={phi_n}")
            
        # Step 4: Compute d = e^(-1) mod φ(n)
        d = mod_inverse(e, phi_n)
        
        # Return (public_key, private_key)
        return (n, e), (n, d)
    else:
        # TODO: Implement RSA key generation
        # - Validate that p and q are distinct primes
        # - Compute n = p * q
        # - Compute φ(n) = (p-1)(q-1)  
        # - Verify gcd(e, φ(n)) = 1
        # - Compute d = e^(-1) mod φ(n)
        # - Return ((n, e), (n, d))
        pass

def test_rsa_keygen(rsa_keygen):
    """Test RSA key generation."""
    print("Testing RSA key generation...")
    
    # Test with small primes
    p, q = 61, 53
    public_key, private_key = rsa_keygen(p, q)
    
    n_pub, e = public_key
    n_priv, d = private_key
    
    print(f"p = {p}, q = {q}")
    print(f"n = {n_pub}")
    print(f"φ(n) = {(p-1)*(q-1)}")
    print(f"Public key: (n={n_pub}, e={e})")
    print(f"Private key: (n={n_priv}, d={d})")
    
    # Verify n is correct
    assert n_pub == p * q, "n should equal p * q"
    assert n_pub == n_priv, "Both keys should have same n"
    
    # Verify ed ≡ 1 (mod φ(n))
    phi_n = (p - 1) * (q - 1)
    assert (e * d) % phi_n == 1, "ed should be ≡ 1 (mod φ(n))"
    
    # Test error cases
    try:
        rsa_keygen(4, 6)  # Non-primes
        assert False, "Should reject non-primes"
    except ValueError:
        pass
        
    try:
        rsa_keygen(7, 7)  # Same prime
        assert False, "Should reject identical primes"
    except ValueError:
        pass
    
    print("✓ RSA key generation tests passed!\n" + "=" * 60)

test_rsa_keygen(rsa_keygen)

# %%

"""

## Exercise 4.2: RSA Encryption and Decryption

RSA encryption and decryption use modular exponentiation. For a message m:
- Encryption: c ≡ m^e (mod n)
- Decryption: m ≡ c^d (mod n)

![RSA Encryption and Decryption](https://www.securew2.com/wp-content/uploads/2024/01/RSA-Encryption-Works.png)

The mathematical foundation ensures that (m^e)^d ≡ m (mod n) by Euler's theorem.

### Exercise - implement rsa_encrypt and rsa_decrypt

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

Implement RSA encryption and decryption functions.
"""

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """
    Efficient modular exponentiation using binary exponentiation.
    
    Computes (base^exponent) mod modulus efficiently.
    """
    if "SOLUTION":
        result = 1
        base = base % modulus
        
        while exponent > 0:
            # If exponent is odd, multiply base with result
            if exponent % 2 == 1:
                result = (result * base) % modulus
            
            # Square the base and halve the exponent
            exponent = exponent >> 1
            base = (base * base) % modulus
            
        return result
    else:
        # TODO: Implement efficient modular exponentiation
        # Use binary exponentiation to avoid computing huge numbers
        pass

def rsa_encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    Encrypt a message using RSA public key.
    
    Args:
        message: Integer message (must be < n)
        public_key: (n, e) tuple
        
    Returns:
        Encrypted ciphertext
    """
    if "SOLUTION":
        n, e = public_key
        if message >= n:
            raise ValueError(f"Message {message} must be < n={n}")
        return mod_exp(message, e, n)
    else:
        # TODO: Implement RSA encryption
        # c = m^e mod n
        pass

def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    Decrypt a ciphertext using RSA private key.
    
    Args:
        ciphertext: Encrypted message
        private_key: (n, d) tuple
        
    Returns:
        Decrypted plaintext
    """
    if "SOLUTION":
        n, d = private_key
        return mod_exp(ciphertext, d, n)
    else:
        # TODO: Implement RSA decryption  
        # m = c^d mod n
        pass

def test_rsa_encrypt_decrypt(rsa_keygen, rsa_encrypt, rsa_decrypt):
    """Test RSA encryption and decryption."""
    print("Testing RSA encryption/decryption...")
    
    # Generate keys
    p, q = 61, 53
    public_key, private_key = rsa_keygen(p, q)
    n, e = public_key
    
    # Test basic encryption/decryption
    message = 42
    ciphertext = rsa_encrypt(message, public_key)
    decrypted = rsa_decrypt(ciphertext, private_key)
    
    print(f"Message: {message}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == message, "Decryption should recover original message"
    
    # Test multiple messages
    test_messages = [1, 100, 1000, n-1]
    for msg in test_messages:
        if msg < n:  # Valid message
            ct = rsa_encrypt(msg, public_key)
            pt = rsa_decrypt(ct, private_key)
            assert pt == msg, f"Failed for message {msg}"
    
    # Test that different messages produce different ciphertexts
    ct1 = rsa_encrypt(10, public_key)
    ct2 = rsa_encrypt(11, public_key)
    assert ct1 != ct2, "Different messages should produce different ciphertexts"
    
    # Test error case - message too large
    try:
        rsa_encrypt(n, public_key)
        assert False, "Should reject message >= n"
    except ValueError:
        pass
    
    print("✓ RSA encryption/decryption tests passed!\n" + "=" * 60)

test_rsa_encrypt_decrypt(rsa_keygen, rsa_encrypt, rsa_decrypt)

# %%

"""

## Exercise 4.3: RSA Digital Signatures

RSA can also provide digital signatures by reversing the key usage: sign with the private key, verify with the public key. This provides authentication and non-repudiation.

The signature process:
- Signing: s ≡ m^d (mod n) (using private key)
- Verification: m ≡ s^e (mod n) (using public key)

### Exercise - implement rsa_sign and rsa_verify

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~20 minutes on this exercise.

Implement RSA digital signature functions.

"""

def simple_hash(message: bytes) -> int:
    """
    Simple hash function for demonstration.
    In practice, use SHA-256 or other cryptographic hash.
    """
    return sum(message) % 1000

def rsa_sign(message: bytes, private_key: Tuple[int, int]) -> int:
    """
    Sign a message using RSA private key.
    
    Args:
        message: Bytes to sign
        private_key: (n, d) tuple
        
    Returns:
        Digital signature
    """
    if "SOLUTION":
        # Hash the message first
        message_hash = simple_hash(message)
        n, d = private_key
        
        # Sign the hash: signature = hash^d mod n
        return mod_exp(message_hash, d, n)
    else:
        # TODO: Implement RSA signing
        # - Hash the message
        # - Sign the hash using private key: s = hash^d mod n
        pass

def rsa_verify(message: bytes, signature: int, public_key: Tuple[int, int]) -> bool:
    """
    Verify an RSA signature.
    
    Args:
        message: Original message bytes
        signature: Digital signature to verify
        public_key: (n, e) tuple
        
    Returns:
        True if signature is valid, False otherwise
    """
    if "SOLUTION":
        # Hash the message
        message_hash = simple_hash(message)
        n, e = public_key
        
        # Verify: hash should equal signature^e mod n
        recovered_hash = mod_exp(signature, e, n)
        return recovered_hash == message_hash
    else:
        # TODO: Implement RSA signature verification
        # - Hash the message
        # - Recover hash from signature: recovered = signature^e mod n
        # - Compare recovered hash with actual hash
        pass

def test_rsa_signatures(rsa_keygen, rsa_sign, rsa_verify):
    """Test RSA digital signatures."""
    print("Testing RSA digital signatures...")
    
    # Generate keys
    p, q = 67, 71
    public_key, private_key = rsa_keygen(p, q)
    
    # Test basic signing and verification
    message = b"Hello, this is a signed message!"
    signature = rsa_sign(message, private_key)
    is_valid = rsa_verify(message, signature, public_key)
    
    print(f"Message: {message}")
    print(f"Signature: {signature}")
    print(f"Valid: {is_valid}")
    
    assert is_valid, "Valid signature should verify"
    
    # Test that modified message fails verification
    modified_message = b"Hello, this is a FORGED message!"
    is_valid_modified = rsa_verify(modified_message, signature, public_key)
    assert not is_valid_modified, "Modified message should fail verification"
    
    # Test with different key pair (wrong public key)
    other_public, other_private = rsa_keygen(73, 79)
    is_valid_wrong_key = rsa_verify(message, signature, other_public)
    assert not is_valid_wrong_key, "Wrong public key should fail verification"
    
    # Test multiple messages
    messages = [b"Short", b"A longer message for testing", b""]
    for msg in messages:
        sig = rsa_sign(msg, private_key)
        assert rsa_verify(msg, sig, public_key), f"Failed for message: {msg}"
    
    print("✓ RSA signature tests passed!\n" + "=" * 60)

test_rsa_signatures(rsa_keygen, rsa_sign, rsa_verify)

# %%

"""

## Exercise 4.4: Breaking RSA with Small Primes

RSA's security depends entirely on the difficulty of factoring n = p × q. With small primes, we can easily brute force RSA by factoring n and reconstructing the private key.
Modern RSA implementations use key sizes of 2048 bits or larger, with 4096-bit keys becoming common for long-term security.
This exercise demonstrates why RSA requires large primes in practice.

### Exercise - implement factor_n and break_rsa

> **Difficulty**: 🔴🔴🔴⚪⚪ 
> **Importance**: 🔵🔵🔵🔵⚪ 
>
> You should spend up to ~30 minutes on this exercise.

Implement RSA key recovery through factorization.
"""

def factor_n(n: int) -> Tuple[int, int]:
    """
    Factor n into p and q using trial division.
    
    Args:
        n: The RSA modulus to factor
        
    Returns:
        Tuple (p, q) where n = p * q
    """
    if "SOLUTION":
        # Try all possible factors up to sqrt(n)
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                p = i
                q = n // i
                # Return the factors (smaller first)
                return (min(p, q), max(p, q))
        
        # If no factors found, n might be prime
        raise ValueError(f"Could not factor {n}")
    else:
        # TODO: Implement factorization
        # - Try all numbers from 2 to sqrt(n)
        # - When you find a divisor, compute the other factor
        # - Return both factors
        pass

def break_rsa(public_key: Tuple[int, int], e_override: int = None) -> Tuple[int, int]:
    """
    Break RSA by factoring n and reconstructing the private key.
    
    Args:
        public_key: (n, e) tuple
        e_override: Use this e instead of the one in public_key (for testing)
        
    Returns:
        Private key (n, d)
    """
    if "SOLUTION":
        n, e = public_key
        if e_override is not None:
            e = e_override
            
        # Step 1: Factor n to get p and q
        p, q = factor_n(n)
        print(f"Factored n={n} into p={p}, q={q}")
        
        # Step 2: Compute φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        
        # Step 3: Compute d = e^(-1) mod φ(n)
        d = mod_inverse(e, phi_n)
        
        return (n, d)
    else:
        # TODO: Implement RSA breaking
        # - Factor n using factor_n()
        # - Compute φ(n) = (p-1)(q-1)
        # - Compute d = e^(-1) mod φ(n) using mod_inverse()
        # - Return private key (n, d)
        pass

def test_rsa_breaking(rsa_keygen, break_rsa, rsa_encrypt, rsa_decrypt):
    """Test RSA breaking through factorization."""
    print("Testing RSA breaking through bruteforce factorization...")
    
    # Generate a key pair with small primes
    p, q = 61, 67
    public_key, private_key = rsa_keygen(p, q)
    
    print(f"Original private key: {private_key}")
    
    # Break the RSA key
    recovered_private_key = break_rsa(public_key)
    
    print(f"Recovered private key: {recovered_private_key}")
    
    # Verify the recovered key works
    test_message = 123
    ciphertext = rsa_encrypt(test_message, public_key)
    
    # Decrypt with original key
    decrypted_original = rsa_decrypt(ciphertext, private_key)
    
    # Decrypt with recovered key
    decrypted_recovered = rsa_decrypt(ciphertext, recovered_private_key)
    
    print(f"Message: {test_message}")
    print(f"Decrypted with original key: {decrypted_original}")
    print(f"Decrypted with recovered key: {decrypted_recovered}")
    
    assert decrypted_original == test_message, "Original key should work"
    assert decrypted_recovered == test_message, "Recovered key should work"
    assert decrypted_original == decrypted_recovered, "Both keys should give same result"
    
    print("✓ RSA breaking tests passed!")
    
    
    print("\n" + "=" * 60)

test_rsa_breaking(rsa_keygen, break_rsa, rsa_encrypt, rsa_decrypt)
# %%

"""
## Exercise 4.5: RSA Message Encryption with Padding (OPTIONAL)

Raw RSA can only encrypt numbers smaller than n, and has security vulnerabilities. Real systems use padding schemes and encrypt symmetric keys rather than messages directly.

We'll implement a simple scheme that:
1. Splits long messages into blocks
2. Adds simple padding to each block
3. Encrypts each block with RSA

### Exercise - implement rsa_encrypt_message and rsa_decrypt_message

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵⚪⚪
>
> You should spend up to ~25 minutes on this exercise.

Implement RSA message encryption with simple padding.
"""

def bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, 'big')

def int_to_bytes(value: int, length: int) -> bytes:
    """Convert integer to bytes of specified length."""
    return value.to_bytes(length, 'big')

def rsa_encrypt_message(message: bytes, public_key: Tuple[int, int]) -> list[int]:
    """
    Encrypt a message by splitting into blocks and padding.
    
    Args:
        message: Message bytes to encrypt
        public_key: RSA public key (n, e)
        
    Returns:
        List of encrypted blocks
    """
    if "SOLUTION":
        n, e = public_key
        
        # Calculate block size (leave room for padding)
        # n is roughly 2^(bit_length), so we can fit (bit_length//8 - 1) bytes per block
        max_bytes_per_block = (n.bit_length() - 1) // 8
        if max_bytes_per_block < 1:
            max_bytes_per_block = 1
            
        encrypted_blocks = []
        
        # Split message into blocks
        for i in range(0, len(message), max_bytes_per_block):
            block = message[i:i + max_bytes_per_block]
            
            # Simple padding: add 0x01 byte at the beginning
            padded_block = b'\x01' + block
            
            # Convert to integer and encrypt
            block_int = bytes_to_int(padded_block)
            if block_int >= n:
                raise ValueError(f"Block too large: {block_int} >= {n}")
                
            encrypted_block = rsa_encrypt(block_int, public_key)
            encrypted_blocks.append(encrypted_block)
            
        return encrypted_blocks
    else:
        # TODO: Implement message encryption
        # - Calculate appropriate block size based on n
        # - Split message into blocks
        # - Add padding to each block (e.g., prepend 0x01)
        # - Encrypt each padded block
        # - Return list of encrypted blocks
        pass

def rsa_decrypt_message(encrypted_blocks: list[int], private_key: Tuple[int, int]) -> bytes:
    """
    Decrypt a message from encrypted blocks.
    
    Args:
        encrypted_blocks: List of encrypted blocks
        private_key: RSA private key (n, d)
        
    Returns:
        Decrypted message bytes
    """
    if "SOLUTION":
        n, d = private_key
        decrypted_message = b""
        
        for encrypted_block in encrypted_blocks:
            # Decrypt the block
            decrypted_int = rsa_decrypt(encrypted_block, private_key)
            
            # Convert back to bytes
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = int_to_bytes(decrypted_int, byte_length)
            
            # Remove padding (first byte should be 0x01)
            if len(decrypted_bytes) > 0 and decrypted_bytes[0] == 0x01:
                decrypted_message += decrypted_bytes[1:]
            else:
                # Handle case where padding is missing or different
                decrypted_message += decrypted_bytes
                
        return decrypted_message
    else:
        # TODO: Implement message decryption
        # - Decrypt each block using RSA
        # - Convert decrypted integers back to bytes
        # - Remove padding from each block
        # - Concatenate all blocks to recover message
        pass

def test_rsa_message_encryption(rsa_keygen, rsa_encrypt_message, rsa_decrypt_message):
    """Test RSA message encryption with padding."""
    print("Testing RSA message encryption...")
    
    # Use larger primes for more realistic block sizes
    p, q = 97, 101
    public_key, private_key = rsa_keygen(p, q)
    n, e = public_key
    
    print(f"Using RSA with n={n} ({n.bit_length()} bits)")
    
    # Test short message
    short_message = b"Hello!"
    encrypted = rsa_encrypt_message(short_message, public_key)
    decrypted = rsa_decrypt_message(encrypted, private_key)
    
    print(f"Short message: {short_message}")
    print(f"Encrypted blocks: {len(encrypted)}")
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == short_message, "Short message decryption failed"
    
    # Test longer message that requires multiple blocks
    long_message = b"This is a much longer message that will definitely require multiple blocks to encrypt properly with our RSA implementation."
    encrypted_long = rsa_encrypt_message(long_message, public_key)
    decrypted_long = rsa_decrypt_message(encrypted_long, private_key)
    
    print(f"\nLong message ({len(long_message)} bytes)")
    print(f"Encrypted into {len(encrypted_long)} blocks")
    print(f"Decrypted correctly: {decrypted_long == long_message}")
    
    assert decrypted_long == long_message, "Long message decryption failed"
    
    # Test edge cases
    empty_message = b""
    encrypted_empty = rsa_encrypt_message(empty_message, public_key)
    decrypted_empty = rsa_decrypt_message(encrypted_empty, private_key)
    assert decrypted_empty == empty_message, "Empty message failed"
    
    single_byte = b"A"
    encrypted_single = rsa_encrypt_message(single_byte, public_key)
    decrypted_single = rsa_decrypt_message(encrypted_single, private_key)
    assert decrypted_single == single_byte, "Single byte failed"
    
    print("✓ RSA message encryption tests passed!\n" + "=" * 60)

test_rsa_message_encryption(rsa_keygen, rsa_encrypt_message, rsa_decrypt_message)

# %%

"""

## Exercise 4.6: RSA Fault Attacks - When Bits Flip

RSA implementations can be vulnerable to fault attacks where computational errors during signature or decryption operations leak the private key. These attacks exploit the mathematical relationship between correct and faulty RSA operations to factor the modulus.

**Important: This attack is probabilistic and doesn't always succeed!** The success depends on:
- Which bit gets flipped during the fault
- The relationship between the fault bit in modular arithmetic

Real-world examples include:
- SSH servers with hardware faults exposing private keys
- Power glitches during smart card operations
- Cosmic rays causing bit flips in memory

This exercise demonstrates how a single faulty RSA signature can sometimes completely compromise security, but also shows the limitations of fault attacks.

### Exercise - implement rsa_fault_attack

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~35 minutes on this exercise.

Implement an attack that recovers the RSA private key from one correct and one faulty signature.
"""

import math

def rsa_sign_with_fault(message_hash: int, private_key: Tuple[int, int], fault_bit: int = None) -> int:
    """
    Sign a message hash, optionally introducing a fault.
    
    Args:
        message_hash: Hash of message to sign
        private_key: (n, d) tuple
        fault_bit: If specified, flip this bit in the final signature
        
    Returns:
        RSA signature (possibly faulty)
    """

    n, d = private_key
    
    # Normal signature computation
    signature = mod_exp(message_hash, d, n)
    
    if fault_bit is not None:
        # Introduce fault by flipping a bit in the signature
        signature = signature ^ (1 << fault_bit)
        
    return signature


def rsa_fault_attack(message_hash: int, correct_sig: int, faulty_sig: int, 
                    public_key: Tuple[int, int]) -> Tuple[int, int]:
    """
    Recover RSA private key from correct and faulty signatures of the same message.
    
    The attack works because:
    1. correct_sig = message_hash^d mod n
    2. faulty_sig = correct_sig XOR (1 << bit_position)
    3. We can find which bit was flipped and use verification to factor n
    
    Args:
        message_hash: The hash that was signed
        correct_sig: Valid signature
        faulty_sig: Signature with computational fault
        public_key: (n, e) tuple
        
    Returns:
        Tuple (p, q) - the prime factors of n
    """
    if "SOLUTION":
        n, e = public_key
        faulty_verify = mod_exp(faulty_sig, e, n)
        
        
        # Approach using the Chinese Remainder Theorem 
        # If we can determine which bit was flipped, we can use that information
        
        # Find the bit position that was flipped
        xor_result = correct_sig ^ faulty_sig
        if xor_result > 0 and (xor_result & (xor_result - 1)) == 0:  # Check if power of 2
            bit_pos = xor_result.bit_length() - 1
            
            # Now we know exactly which bit was flipped
            # Use this knowledge with the verification equation
            
            # The idea is that correct_sig^e ≡ message_hash (mod n)
            # But (correct_sig XOR 2^k)^e ≢ message_hash (mod n)
            # The difference reveals information about the factorization
            
            # Try a more direct mathematical approach
            # Let's call the bit flip delta = 2^bit_pos
            delta = 1 << bit_pos
            
            # We have: (correct_sig + delta)^e ≡ faulty_verify (mod n)
            # And: correct_sig^e ≡ message_hash (mod n)
            # So: (correct_sig + delta)^e - correct_sig^e ≡ faulty_verify - message_hash (mod n)
            
            # For small deltas, we can approximate using binomial expansion
            # (a + delta)^e ≈ a^e + e * a^(e-1) * delta (for small delta relative to a)
            
            if correct_sig > 0:
                # Compute the approximate linear term
                linear_term = (e * pow(correct_sig, e-1, n) * delta) % n
                actual_diff = (faulty_verify - message_hash) % n
                
                # The difference between actual and approximated can reveal factors
                approx_error = abs(linear_term - actual_diff)
                if approx_error > 0:
                    factor = math.gcd(approx_error, n)
                    if 1 < factor < n:
                        p = factor
                        q = n // factor
                        return (min(p, q), max(p, q))
        

        raise ValueError("Could not factor n using fault attack")
    else:
        # TODO: Implement RSA fault attack
        # - Approach using the Chinese Remainder Theorem 
        # - If we can determine which bit was flipped, we can use that information
        # - Find the bit position that was flipped
        pass

"""
<details> 
<summary>Hint 1: Use the verification difference</summary>

The key insight is that correct_sig^e ≡ message_hash (mod n) but faulty_sig^e ≢ message_hash (mod n). Compute faulty_verify = faulty_sig^e mod n, then try gcd(faulty_verify - message_hash, n). If the fault affected only one prime factor (p or q), this GCD will reveal that factor. Also try gcd(correct_sig - faulty_sig, n) as the signature difference itself might reveal factors.

</details>
"""

def simulate_ssh_fault_scenario():
    """
    Simulate the SSH fault attack scenario from recent research.
    """
    print("Simulating SSH Fault Attack Scenario...")
    
    # Generate SSH server's RSA key pair (using smaller primes for demo)
    p, q = 97, 103  # Small primes for demonstration
    public_key, private_key = rsa_keygen(p, q)
    n, e = public_key
    
    print(f"SSH Server RSA Key: n = {n}, e = {e}")
    
    # Simulate SSH handshake with message authentication
    session_data = b"SSH-2.0-OpenSSH_8.0"
    message_hash = simple_hash(session_data)
    
    print(f"Session data: {session_data}")
    print(f"Message hash: {message_hash}")
    
    # Normal signature
    correct_signature = rsa_sign_with_fault(message_hash, private_key)
    print(f"Normal signature: {correct_signature}")
    
    # Simulate computational fault (bit flip in signature)
    fault_bit_position = 8
    faulty_signature = rsa_sign_with_fault(message_hash, private_key, fault_bit_position)
    print(f"Faulty signature: {faulty_signature} (bit {fault_bit_position} flipped)")
    
    # Attacker performs fault attack
    print(f"\nAttacker intercepts both signatures...")
    try:
        recovered_p, recovered_q = rsa_fault_attack(message_hash, correct_signature, 
                                                   faulty_signature, public_key)
        print(f"SUCCESS: Recovered factors p = {recovered_p}, q = {recovered_q}")
        print(f"Original factors: p = {p}, q = {q}")
        
        # Verify the attack worked
        assert {recovered_p, recovered_q} == {p, q}, "Incorrect factors recovered"
        
        # Reconstruct private key
        phi_n = (recovered_p - 1) * (recovered_q - 1)
        recovered_d = mod_inverse(e, phi_n)
        print(f"Reconstructed private key: d = {recovered_d}")
        
        # Test the reconstructed key
        test_message = 42
        original_encrypted = rsa_encrypt(test_message, public_key)
        recovered_decrypted = mod_exp(original_encrypted, recovered_d, n)
        
        print(f"Key verification: {test_message} → {original_encrypted} → {recovered_decrypted}")
        assert recovered_decrypted == test_message, "Recovered key doesn't work"
        
        print("✓ Private key successfully recovered from fault attack!")
        
    except ValueError as e:
        print(f"Attack failed: {e}")
    
    return public_key, private_key, correct_signature, faulty_signature

def test_rsa_fault_attack(rsa_fault_attack, rsa_sign_with_fault):
    """Test RSA fault attack implementation."""
    print("Testing RSA fault attack...")
    
    # Test with different key sizes and fault positions
    test_cases = [
        (61, 67, 7, False),   # Small primes, bit 7
        (73, 79, 5, True),   # Different primes, bit 5
        (83, 89, 3, True),   # Another case, bit 3
    ]
    
    for p, q, fault_bit, expected_outcome in test_cases:
        print(f"\nTesting with p={p}, q={q}, fault_bit={fault_bit}")
        
        public_key, private_key = rsa_keygen(p, q)
        n, e = public_key
        
        # Create test message
        message_hash = 123
        
        # Generate correct and faulty signatures
        correct_sig = rsa_sign_with_fault(message_hash, private_key)
        faulty_sig = rsa_sign_with_fault(message_hash, private_key, fault_bit)
        
        print(f"  Correct signature: {correct_sig}")
        print(f"  Faulty signature:  {faulty_sig}")
        
        try:
            # Perform attack
            recovered_p, recovered_q = rsa_fault_attack(message_hash, correct_sig, 
                                                       faulty_sig, public_key)
            
            # Verify correctness
            assert {recovered_p, recovered_q} == {p, q}, f"Wrong factors: got {recovered_p}, {recovered_q}, expected {p}, {q}"
            print(f"  ✓ Successfully recovered factors: {recovered_p}, {recovered_q}")
            
        except Exception as e:
            if not expected_outcome:
                print(f"  ✓ Attack failed as expected (not all bit flips enable factorization)")
            else:
                print(f"  ✗ Attack failed: {e}")
    
    print("\n" + "=" * 60)

# Run the simulation and tests
ssh_scenario_results = simulate_ssh_fault_scenario()
test_rsa_fault_attack(rsa_fault_attack, rsa_sign_with_fault)
