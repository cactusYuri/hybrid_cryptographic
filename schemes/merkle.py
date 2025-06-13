import time
from typing import Any

from .base_scheme import AccumulatorScheme
from utils.crypto import get_hash

class MerkleTree(AccumulatorScheme):
    """
    A simplified Merkle Tree implementation for benchmarking.
    - Does not handle empty states or non-power-of-two leaf counts perfectly,
      but pads to the nearest power of two.
    - Proofs are lists of sibling hashes.
    """

    def __init__(self, state: list[bytes]):
        super().__init__(state)
        self.leaves = [get_hash(s) for s in self.state]
        self.tree = []

    def create(self):
        start_time = time.perf_counter()
        
        num_leaves = len(self.leaves)
        if num_leaves == 0:
            self.tree = [[]]
            self.accumulator = get_hash(b'')
            self.prover_time = time.perf_counter() - start_time
            return

        next_pow_2 = 1 << (num_leaves - 1).bit_length() if num_leaves > 0 else 1
        self.padded_leaves = self.leaves + [b'\x00' * 32] * (next_pow_2 - num_leaves)
        
        self.tree = [self.padded_leaves]
        level = self.padded_leaves
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i+1]
                parent = get_hash(left + right)
                next_level.append(parent)
            self.tree.append(next_level)
            level = next_level
        
        self.accumulator = self.tree[-1][0] if self.tree and self.tree[-1] else None
        self.prover_time = time.perf_counter() - start_time

    def get_leaf_index(self, element: bytes) -> int:
        """Helper to find the index of an element's hash in the padded leaf list."""
        leaf_hash = get_hash(element)
        try:
            # Find the original state index first
            state_idx = self.state.index(element)
            # Now find the hash at that index in the leaves list
            if state_idx < len(self.leaves) and self.leaves[state_idx] == leaf_hash:
                 # This is a bit of a shortcut. Assumes leaves are in same order as state.
                 return state_idx
        except ValueError:
            return -1
        return -1

    def prove_membership(self, element: bytes) -> list[bytes]:
        start_time = time.perf_counter()
        
        idx = self.get_leaf_index(element)
        if idx == -1:
            self.prover_time += time.perf_counter() - start_time
            return None

        proof = []
        for level in self.tree[:-1]:
            is_right_node = idx % 2
            sibling_idx = idx - 1 if is_right_node else idx + 1
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            idx //= 2
            
        self.prover_time += time.perf_counter() - start_time
        self.proof_size = self.get_proof_size(proof)
        return proof

    def verify_membership(self, element: bytes, proof: list[bytes]) -> bool:
        start_time = time.perf_counter()
        
        leaf_hash = get_hash(element)
        
        # Find the original index of the leaf hash to determine path
        try:
            # This is a shortcut for verification. A real client wouldn't know the index.
            # They would be given the index or a path. For this simulation, we find it.
            leaf_hash = get_hash(element)
            idx = self.tree[0].index(leaf_hash)
        except ValueError:
             self.verifier_time += time.perf_counter() - start_time
             return False

        computed_hash = leaf_hash
        for sibling_hash in proof:
            is_right_node = idx % 2
            if is_right_node:
                computed_hash = get_hash(sibling_hash + computed_hash)
            else:
                computed_hash = get_hash(computed_hash + sibling_hash)
            idx //= 2

        is_valid = computed_hash == self.accumulator
        self.verifier_time += time.perf_counter() - start_time
        return is_valid

    def update(self, element: bytes, new_element: bytes):
        """
        Efficiently updates the Merkle tree for a single element change.
        Complexity: O(log N)
        """
        start_time = time.perf_counter()

        try:
            idx = self.state.index(element)
            self.state[idx] = new_element
            leaf_hash = get_hash(new_element)
            self.leaves[idx] = leaf_hash
        except ValueError:
            # For this efficient update, we assume the element exists.
            # Handling additions/deletions requires resizing, which is more complex.
            # This implementation focuses on benchmarking in-place updates.
            self.prover_time += time.perf_counter() - start_time
            return

        # Update the leaf in the tree's base level
        self.tree[0][idx] = leaf_hash
        
        # Propagate the change up to the root
        for i in range(len(self.tree) - 1):
            is_right_node = idx % 2
            parent_idx = (idx - 1) // 2 if is_right_node else idx // 2
            
            sibling_idx = idx - 1 if is_right_node else idx + 1
            
            left = self.tree[i][sibling_idx if is_right_node else idx]
            right = self.tree[i][idx if is_right_node else sibling_idx]

            new_parent_hash = get_hash(left + right)

            if self.tree[i+1][parent_idx] == new_parent_hash:
                # No change in parent hash, so we can stop
                break

            self.tree[i+1][parent_idx] = new_parent_hash
            idx = parent_idx
        
        self.accumulator = self.tree[-1][0]
        self.prover_time += time.perf_counter() - start_time