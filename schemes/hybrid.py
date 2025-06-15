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
        # Create segments and distribute initial state
        segment_states = [[] for _ in range(num_segments)]
        for element in self.state:
            segment_idx = self._get_segment_index(element)
            segment_states[segment_idx].append(element)
        
        self.segments: list[RsaAccumulator] = [RsaAccumulator(s) for s in segment_states]
        self.top_level_tree: MerkleTree = None

    def _get_segment_index(self, element: bytes) -> int:
        """Determines which segment an element belongs to based on its hash."""
        return bytes_to_int(get_hash(element)) % self.num_segments

    def create(self):
        segment_accumulator_digests = []
        for segment in self.segments:
            segment.create()
            segment_digest = int_to_bytes(segment.accumulator)
            segment_accumulator_digests.append(segment_digest)
        
        self.top_level_tree = MerkleTree(segment_accumulator_digests)
        self.top_level_tree.create()
        
        self.accumulator = self.top_level_tree.accumulator

    def prove_membership(self, element: bytes) -> HybridProof | None:
        segment_idx = self._get_segment_index(element)
        segment = self.segments[segment_idx]
        
        segment_proof = segment.prove_membership(element)
        if segment_proof is None:
            return None

        segment_digest = int_to_bytes(segment.accumulator)
        top_level_proof = self.top_level_tree.prove_membership(segment_digest)
        if top_level_proof is None:
            return None

        return HybridProof(
            segment_proof=segment_proof, 
            top_level_proof=top_level_proof,
            segment_accumulator_val=segment.accumulator
        )

    def verify_membership(self, element: bytes, proof: HybridProof) -> bool:
        segment_accumulator_digest_bytes = int_to_bytes(proof.segment_accumulator_val)
        
        is_top_level_valid = self.top_level_tree.verify_membership(
            segment_accumulator_digest_bytes, proof.top_level_proof
        )
        
        if not is_top_level_valid:
            return False
            
        verifier_segment = RsaAccumulator([])
        verifier_segment.accumulator = proof.segment_accumulator_val
        
        return verifier_segment.verify_membership(element, proof.segment_proof)

    def update(self, old_element: bytes, new_element: bytes):
        """
        Updates the hybrid scheme by replacing old_element with new_element.
        """
        old_segment_idx = self._get_segment_index(old_element)
        new_segment_idx = self._get_segment_index(new_element)

        old_segment = self.segments[old_segment_idx]
        old_segment_digest_before = int_to_bytes(old_segment.accumulator)

        if old_segment_idx == new_segment_idx:
            old_segment.update(old_element, new_element)
            new_segment_digest = int_to_bytes(old_segment.accumulator)
            self.top_level_tree.update(old_segment_digest_before, new_segment_digest)
        else:
            new_segment = self.segments[new_segment_idx]
            new_segment_digest_before = int_to_bytes(new_segment.accumulator)
            
            old_segment.state.remove(old_element)
            old_segment.create()
            new_segment.state.append(new_element)
            new_segment.create()

            old_segment_digest_after = int_to_bytes(old_segment.accumulator)
            new_segment_digest_after = int_to_bytes(new_segment.accumulator)
            
            self.top_level_tree.update(old_segment_digest_before, old_segment_digest_after)
            self.top_level_tree.update(new_segment_digest_before, new_segment_digest_after)

        try:
            idx = self.state.index(old_element)
            self.state[idx] = new_element
        except ValueError:
            pass

        self.accumulator = self.top_level_tree.accumulator 