import time
from typing import Any, Dict

from .base_scheme import AccumulatorScheme
from utils.crypto import get_hash

class MerkleTree(AccumulatorScheme):
    """
    A simplified Merkle Tree implementation for benchmarking.
    - Pads to the nearest power of two.
    - Uses a hash map for O(1) leaf lookups.
    """

    def __init__(self, state: list[bytes]):
        super().__init__(state)
        self.leaves = [get_hash(s) for s in self.state]
        self.tree: list[list[bytes]] = []
        self.leaf_to_index: Dict[bytes, int] = {}

    def create(self):
        num_leaves = len(self.leaves)
        if num_leaves == 0:
            self.tree = [[]]
            self.accumulator = get_hash(b'')
            return

        next_pow_2 = 1 << (num_leaves - 1).bit_length() if num_leaves > 0 else 1
        self.padded_leaves = self.leaves + [b'\x00' * 32] * (next_pow_2 - num_leaves)
        
        # Build the leaf_to_index map
        for i, leaf_hash in enumerate(self.padded_leaves):
            # We only map original leaves, not padding.
            if i < num_leaves:
                self.leaf_to_index[leaf_hash] = i

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

    def prove_membership(self, element: bytes) -> list[bytes] | None:
        leaf_hash = get_hash(element)
        idx = self.leaf_to_index.get(leaf_hash)
        
        if idx is None:
            return None

        proof = []
        for level in self.tree[:-1]:
            is_right_node = idx % 2
            sibling_idx = idx - 1 if is_right_node else idx + 1
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            idx //= 2
            
        return proof

    def verify_membership(self, element: bytes, proof: list[bytes]) -> bool:
        leaf_hash = get_hash(element)
        idx = self.leaf_to_index.get(leaf_hash)

        if idx is None:
             # If the element isn't supposed to be in the tree, we can't find its index.
             # Verification should fail. A more robust way might be to pass index in proof.
             # For this benchmark, we assume verifier can look it up.
             return False

        computed_hash = leaf_hash
        for sibling_hash in proof:
            is_right_node = idx % 2
            if is_right_node:
                computed_hash = get_hash(sibling_hash + computed_hash)
            else:
                computed_hash = get_hash(computed_hash + sibling_hash)
            idx //= 2

        return computed_hash == self.accumulator

    def update(self, old_element: bytes, new_element: bytes):
        """
        Efficiently updates the Merkle tree for a single element change.
        The cryptographic part of this update is O(log N).
        Note: The self.state.index call is O(N), making state management inefficient.
        For a real-world application, a dictionary or other mapping should be used
        to track element indices for O(1) lookup.
        """
        old_leaf_hash = get_hash(old_element)
        idx = self.leaf_to_index.get(old_leaf_hash)

        if idx is None:
            # Element not found, cannot update.
            return
        
        # Update state and get new leaf hash
        try:
            # This is an O(N) operation.
            state_idx = self.state.index(old_element)
            self.state[state_idx] = new_element
        except ValueError:
            return # Should not happen if idx was found

        new_leaf_hash = get_hash(new_element)

        # Update the leaf in the tree's base level and the lookup map
        self.tree[0][idx] = new_leaf_hash
        del self.leaf_to_index[old_leaf_hash]
        self.leaf_to_index[new_leaf_hash] = idx
        
        # Propagate the change up to the root
        current_idx = idx
        for i in range(len(self.tree) - 1):
            is_right_node = current_idx % 2
            parent_idx = (current_idx - 1) // 2 if is_right_node else current_idx // 2
            
            sibling_idx = current_idx - 1 if is_right_node else current_idx + 1
            
            left_child_idx = sibling_idx if is_right_node else current_idx
            right_child_idx = current_idx if is_right_node else sibling_idx
            
            left = self.tree[i][left_child_idx]
            right = self.tree[i][right_child_idx]

            new_parent_hash = get_hash(left + right)

            if self.tree[i+1][parent_idx] == new_parent_hash:
                # No change in parent hash, so we can stop
                break

            self.tree[i+1][parent_idx] = new_parent_hash
            current_idx = parent_idx
        
        self.accumulator = self.tree[-1][0]