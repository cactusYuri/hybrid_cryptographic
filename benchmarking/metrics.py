from dataclasses import dataclass, field
from typing import TypedDict

@dataclass
class BenchmarkResults:
    """
    Stores the results of a single benchmark run for one scheme.
    """
    scheme_name: str
    state_size: int
    prover_time: float = 0.0  # Time to create accumulator
    update_time: float = 0.0  # Time to update accumulator
    verifier_time: float = 0.0 # Time to verify one proof
    proof_size: int = 0 # Size of one proof in bytes

class ExperimentResults(TypedDict):
    """
    A dictionary to hold all results from an experiment.
    Maps a scheme name to a list of BenchmarkResults.
    """
    merkle: list[BenchmarkResults]
    rsa: list[BenchmarkResults]
    hybrid: list[BenchmarkResults]
    verkle: list[BenchmarkResults] 