import random
import time
from tqdm import tqdm
import numpy as np

from schemes.base_scheme import AccumulatorScheme
from schemes.merkle import MerkleTree
from schemes.rsa_accumulator import RsaAccumulator
from schemes.hybrid import HybridScheme
from schemes.verkle import VerkleTree
from simulation.simulator import generate_random_state
from .metrics import BenchmarkResults, ExperimentResults

def run_benchmark():
    """
    Runs the full benchmark suite for all schemes and state sizes.
    """
    state_sizes = [100, 1000, 5000, 10000, 50000] 
    num_runs = 5  # Number of runs to average for each data point
    update_fraction = 0.1 # 10% of the state will be updated
    
    schemes_to_test = {
        "merkle": MerkleTree,
        "rsa": RsaAccumulator,
        "hybrid": HybridScheme,
        "verkle": VerkleTree
    }

    all_results: ExperimentResults = { name: [] for name in schemes_to_test.keys() }

    with tqdm(total=len(schemes_to_test) * len(state_sizes), desc="Running Benchmarks") as pbar:
        for name, scheme_class in schemes_to_test.items():
            for size in state_sizes:
                pbar.set_description(f"Benchmarking {name} (N={size})")
                
                run_creation_times, run_update_times, run_verifier_times, run_proof_sizes = [], [], [], []

                for _ in range(num_runs):
                    initial_state = generate_random_state(size)
                    
                    # --- 1. Measure Creation Time ---
                    creation_start_time = time.perf_counter()
                    scheme = scheme_class(initial_state)
                    scheme.create()
                    creation_time = time.perf_counter() - creation_start_time
                    run_creation_times.append(creation_time)

                    # --- 2. Measure Update Time for multiple single updates ---
                    num_updates = int(size * update_fraction)
                    elements_to_update = random.sample(initial_state, num_updates)
                    
                    # Reset prover timer before starting updates
                    scheme.prover_time = 0.0 
                    
                    update_start_time = time.perf_counter()
                    
                    # Add a nested progress bar for the update loop
                    update_iterator = tqdm(elements_to_update, desc=f"Updating (run {_ + 1}/{num_runs})", leave=False)
                    for element_to_update in update_iterator:
                        new_element = element_to_update + b'-updated'
                        # For schemes that still use add/delete, we simulate it
                        if hasattr(scheme, 'update') and callable(getattr(scheme, 'update')) and 'new_element' in scheme.update.__code__.co_varnames:
                             scheme.update(element_to_update, new_element)
                        else: # Fallback for RSA/Hybrid style
                             scheme.update([new_element], [element_to_update])

                    update_time = time.perf_counter() - update_start_time
                    # We report the average time per update
                    run_update_times.append(update_time / num_updates if num_updates > 0 else 0)
                    
                    # --- 3. Measure Proof and Verification Time ---
                    element_to_prove = random.choice(scheme.state)
                    
                    scheme.verifier_time = 0.0 # Reset verifier timer
                    proof = scheme.prove_membership(element_to_prove)
                    
                    is_valid = False
                    if proof is not None:
                        is_valid = scheme.verify_membership(element_to_prove, proof)
                    
                    if not is_valid and name != "verkle": # Verkle is mocked
                         print(f"WARNING: Verification failed for {name} with state size {size}")

                    run_verifier_times.append(scheme.verifier_time)
                    run_proof_sizes.append(scheme.proof_size)

                # --- 4. Average results and store ---
                result = BenchmarkResults(
                    scheme_name=name,
                    state_size=size,
                    prover_time=np.mean(run_creation_times),
                    update_time=np.mean(run_update_times),
                    verifier_time=np.mean(run_verifier_times),
                    proof_size=np.mean(run_proof_sizes)
                )
                all_results[name].append(result)
                pbar.update(1)

    return all_results 