import hashlib
from Crypto.Util import number
import random

def get_hash(data: bytes) -> bytes:
    """Computes the SHA-256 hash of the input data."""
    return hashlib.sha256(data).digest()

def bytes_to_int(b: bytes) -> int:
    """Converts bytes to an integer."""
    return int.from_bytes(b, 'big')

def int_to_bytes(i: int) -> bytes:
    """Converts an integer to bytes."""
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

def prime_representatives(elements: list[bytes], bit_length: int) -> list[int]:
    """
    Maps a list of byte strings to prime numbers in a deterministic way.
    This is a simplified mapping function. A robust implementation would use a
    more sophisticated and secure hash-to-prime function.
    """
    primes = []
    for el_hash in elements:
        # Use the element's hash as a seed for a deterministic RNG.
        # This makes the prime generation deterministic for a given element.
        seed = bytes_to_int(el_hash)
        rng = random.Random(seed)

        # The randfunc for getPrime needs to be a function that returns n random bytes.
        randfunc = lambda n: rng.getrandbits(n * 8).to_bytes(n, 'big')
        
        # Generate a prime using the deterministic RNG.
        prime = number.getPrime(bit_length, randfunc=randfunc)
        primes.append(prime)
    return primes

def product(numbers: list[int]) -> int:
    """Computes the product of a list of numbers."""
    res = 1
    for n in numbers:
        res *= n
    return res 