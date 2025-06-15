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
    """
    Computes the product of a list of numbers.
    Uses a product tree for lists longer than a certain threshold for efficiency.
    """
    if not numbers:
        return 1
    # For short lists, linear product is fine. For longer lists, product tree is faster.
    if len(numbers) < 64:
        res = 1
        for n in numbers:
            res *= n
        return res
    else:
        return product_tree(numbers)

def product_tree(numbers: list[int]) -> int:
    """
    Computes the product of a list of numbers using a product tree algorithm.
    This is much more efficient than a linear product for large lists.
    """
    num = len(numbers)
    if num == 0:
        return 1
    if num == 1:
        return numbers[0]
    
    mid = num // 2
    left_prod = product_tree(numbers[:mid])
    right_prod = product_tree(numbers[mid:])
    
    return left_prod * right_prod 