import time
from typing import Any, NamedTuple

from .base_scheme import AccumulatorScheme
from .merkle import MerkleTree
from .rsa_accumulator import RsaAccumulator
from utils.crypto import get_hash, bytes_to_int, int_to_bytes

class HybridProof(NamedTuple):
    segment_proof: int
    top_level_proof: list[bytes]
    segment_accumulator_val: int

class HybridScheme(AccumulatorScheme):
    """
    The proposed Hybrid Accumulator Scheme (Merkle-Accumulator Hybrid Tree).
    - A top-level Merkle tree commits to segment accumulators.
    - Each segment is an RSA accumulator.
    """

    def __init__(self, state: list[bytes], num_segments: int = 16):
        super().__init__(state)
        self.num_segments = num_segments
        self.segments: list[RsaAccumulator] = [RsaAccumulator([]) for _ in range(num_segments)]
        self.top_level_tree: MerkleTree = None
        
        # Distribute initial state into segments
        for element in self.state:
            segment_idx = self._get_segment_index(element)
            self.segments[segment_idx].state.append(element)

    def _get_segment_index(self, element: bytes) -> int:
        """Determines which segment an element belongs to based on its hash."""
        return bytes_to_int(get_hash(element)) % self.num_segments

    def create(self):
        start_time = time.perf_counter()

        segment_accumulator_digests = []
        for segment in self.segments:
            segment.create()
            segment_digest = int_to_bytes(segment.accumulator)
            segment_accumulator_digests.append(segment_digest)
        
        self.top_level_tree = MerkleTree(segment_accumulator_digests)
        self.top_level_tree.create()
        
        self.accumulator = self.top_level_tree.accumulator
        self.prover_time = time.perf_counter() - start_time

    def prove_membership(self, element: bytes) -> HybridProof:
        start_time = time.perf_counter()

        segment_idx = self._get_segment_index(element)
        segment = self.segments[segment_idx]
        
        segment_proof = segment.prove_membership(element)
        if segment_proof is None:
            self.prover_time += time.perf_counter() - start_time
            return None

        segment_digest = int_to_bytes(segment.accumulator)
        top_level_proof = self.top_level_tree.prove_membership(segment_digest)

        proof = HybridProof(
            segment_proof=segment_proof, 
            top_level_proof=top_level_proof,
            segment_accumulator_val=segment.accumulator
        )
        self.prover_time += time.perf_counter() - start_time
        self.proof_size = self.get_proof_size(proof)
        return proof

    def verify_membership(self, element: bytes, proof: HybridProof) -> bool:
        start_time = time.perf_counter()
        segment_accumulator_digest_bytes = int_to_bytes(proof.segment_accumulator_val)
        
        is_top_level_valid = self.top_level_tree.verify_membership(
            segment_accumulator_digest_bytes, proof.top_level_proof
        )
        
        if not is_top_level_valid:
            self.verifier_time += time.perf_counter() - start_time
            return False
            
        segment_idx = self._get_segment_index(element)
        verifier_segment = self.segments[segment_idx]
        
        original_acc = verifier_segment.accumulator
        verifier_segment.accumulator = proof.segment_accumulator_val
        is_segment_valid = verifier_segment.verify_membership(element, proof.segment_proof)
        verifier_segment.accumulator = original_acc
        
        is_valid = is_top_level_valid and is_segment_valid
        self.verifier_time += time.perf_counter() - start_time
        return is_valid

    def update(self, additions: list[bytes], deletions: list[bytes]):
        start_time = time.perf_counter()
        updates = {}
        for element in additions:
            idx = self._get_segment_index(element)
            if idx not in updates: updates[idx] = {'add': [], 'del': []}
            updates[idx]['add'].append(element)

        for element in deletions:
            idx = self._get_segment_index(element)
            if idx not in updates: updates[idx] = {'add': [], 'del': []}
            updates[idx]['del'].append(element)

        new_top_level_leaves = [int_to_bytes(s.accumulator) for s in self.segments]

        for segment_idx, change in updates.items():
            if segment_idx < len(self.segments):
                segment = self.segments[segment_idx]
                segment.update(change['add'], change['del'])
                new_top_level_leaves[segment_idx] = int_to_bytes(segment.accumulator)

        # Update the scheme's own state representation
        current_state_set = set(self.state)
        current_state_set.difference_update(deletions)
        current_state_set.update(additions)
        self.state = list(current_state_set)

        self.top_level_tree = MerkleTree(new_top_level_leaves)
        self.top_level_tree.create()
        self.accumulator = self.top_level_tree.accumulator
        
        self.prover_time += time.perf_counter() - start_time

    def get_proof_size(self, proof: HybridProof) -> int:
        # This method needs to be implemented to return the size of the proof in bytes
        # For now, we'll return a placeholder value
        return 100  # Placeholder value, actual implementation needed

    def get_verifier_time(self) -> float:
        return self.verifier_time

    def get_prover_time(self) -> float:
        return self.prover_time

    def get_proof_size(self, proof: HybridProof) -> int:
        # This method needs to be implemented to return the size of the proof in bytes
        # For now, we'll return a placeholder value
        return 100  # Placeholder value, actual implementation needed 