import time
from typing import Any
from Crypto.Util import number

from .base_scheme import AccumulatorScheme
from utils.crypto import prime_representatives, product, get_hash

# For simulation, we can use a fixed, pre-generated RSA modulus.
# In a real system, this would be part of a trusted setup ceremony.
RSA_MODULUS_BITS = 2048
PRIME_BITS = 128 # The size of primes representing elements

class RsaAccumulator(AccumulatorScheme):
    """
    A dynamic RSA Accumulator.
    - Requires a trusted setup for the modulus N.
    - Elements are mapped to unique prime numbers.
    """

    def __init__(self, state: list[bytes]):
        super().__init__(state)
        # --- Trusted Setup ---
        p = number.getPrime(RSA_MODULUS_BITS // 2)
        q = number.getPrime(RSA_MODULUS_BITS // 2)
        while p == q:
            q = number.getPrime(RSA_MODULUS_BITS // 2)
        self.N = p * q
        self.phi_n = (p - 1) * (q - 1)
        self.g = 3
        # --- End Trusted Setup ---

        self.prime_map = {} # Maps element hash to its prime representative
        self.accumulator = self.g

    def _map_to_primes(self, elements: list[bytes]):
        """Maps elements to primes and stores them."""
        hashes = [get_hash(e) for e in elements]
        new_primes = prime_representatives([h for h in hashes if h not in self.prime_map], PRIME_BITS)
        
        new_prime_idx = 0
        for h in hashes:
            if h not in self.prime_map:
                self.prime_map[h] = new_primes[new_prime_idx]
                new_prime_idx += 1

    def create(self):
        start_time = time.perf_counter()

        self._map_to_primes(self.state)
        
        if not self.state:
            self.accumulator = self.g
            self.prover_time = time.perf_counter() - start_time
            return

        prime_prod = product([self.prime_map[get_hash(s)] for s in self.state])
        self.accumulator = pow(self.g, prime_prod, self.N)
        
        self.prover_time = time.perf_counter() - start_time

    def prove_membership(self, element: bytes) -> int:
        start_time = time.perf_counter()
        
        element_hash = get_hash(element)
        if element_hash not in self.prime_map:
            self.prover_time += time.perf_counter() - start_time
            return None # Element not in accumulator

        x = self.prime_map[element_hash]
        
        # Calculate product of all other primes
        other_primes_prod = product([self.prime_map[get_hash(s)] for s in self.state if get_hash(s) != element_hash])
        
        # The witness is g^(product of other primes)
        witness = pow(self.g, other_primes_prod, self.N)

        self.prover_time += time.perf_counter() - start_time
        self.proof_size = self.get_proof_size(witness)
        return witness

    def verify_membership(self, element: bytes, proof: int) -> bool:
        start_time = time.perf_counter()
        
        element_hash = get_hash(element)
        if element_hash not in self.prime_map:
            self._map_to_primes([element])

        x = self.prime_map[element_hash]
        witness = proof
        
        is_valid = pow(witness, x, self.N) == self.accumulator
        
        self.verifier_time += time.perf_counter() - start_time
        return is_valid

    def update(self, additions: list[bytes], deletions: list[bytes]):
        start_time = time.perf_counter()

        # Handle additions
        if additions:
            self._map_to_primes(additions)
            additions_prod = product([self.prime_map[get_hash(s)] for s in additions])
            self.accumulator = pow(self.accumulator, additions_prod, self.N)

        # Handle deletions
        if deletions:
            deleted_hashes = {get_hash(d) for d in deletions}
            
            # This check is important. Attempting to get a prime for an element that
            # was never in the accumulator will fail.
            primes_to_remove = [self.prime_map[h] for h in deleted_hashes if h in self.prime_map]
            
            if primes_to_remove:
                deletions_prod = product(primes_to_remove)
                # To "divide" in the exponent, we multiply by the modular inverse.
                # This requires calculating `d_prod^-1 mod phi(N)`.
                inv_deletions_prod = pow(deletions_prod, -1, self.phi_n)
                self.accumulator = pow(self.accumulator, inv_deletions_prod, self.N)

        # Update internal state representation
        current_state_set = set(self.state)
        current_state_set.difference_update(deletions)
        current_state_set.update(additions)
        self.state = list(current_state_set)
        
        # Remove deleted primes from map
        deleted_hashes_for_map = {get_hash(d) for d in deletions}
        for h in deleted_hashes_for_map:
            if h in self.prime_map:
                del self.prime_map[h]

        self.prover_time += time.perf_counter() - start_time

    def get_proof_size(self, proof: int) -> int:
        # This method should be implemented to return the size of the proof in bytes
        # For now, we'll return a placeholder value
        return 128  # Placeholder value, actual implementation needed

    def get_proof_size_in_bits(self, proof: int) -> int:
        # This method should be implemented to return the size of the proof in bits
        # For now, we'll return a placeholder value
        return 1024  # Placeholder value, actual implementation needed 