import random
import time
from tqdm import tqdm
import numpy as np

from schemes.base_scheme import AccumulatorScheme
from schemes.merkle import MerkleTree
from schemes.rsa_accumulator import RsaAccumulator, RsaAccumulatorTrapdoored
from schemes.hybrid import HybridScheme
from schemes.verkle import VerkleTree
from simulation.simulator import generate_random_state
from .metrics import BenchmarkResults, ExperimentResults

def run_benchmark():
    """
    Runs the full benchmark suite for all schemes and state sizes.
    """
    # NOTE: state_sizes is currently small for quick tests. 
    # To reproduce paper results, use: [100, 1000, 5000, 10000, 50000]
    state_sizes = [100, 500, 1000] 
    num_runs = 5
    # NOTE: The paper mentions updating 10% of the state. This implementation uses
    # a fixed number of updates. This will affect results for larger state sizes.
    # To match the paper, you could use: num_updates = int(size * 0.1)
    FIXED_UPDATES = 100  # Max updates per run (or less if state smaller)
    
    schemes_to_test = {
        "Merkle Tree": MerkleTree,
        "RSA (Trapdoor-free)": RsaAccumulator,
        "RSA (Batched)": RsaAccumulatorTrapdoored,
        "Hybrid": HybridScheme,
        "Verkle (Simulated)": VerkleTree
    }

    all_results: ExperimentResults = { name: [] for name in schemes_to_test.keys() }

    with tqdm(total=len(schemes_to_test) * len(state_sizes), desc="Running Benchmarks") as pbar:
        for size in state_sizes:
            for name, scheme_class in schemes_to_test.items():
                # Skip the slow trapdoor-free RSA for large states to save time
                if name == "RSA (Trapdoor-free)" and size > 5000:
                    pbar.update(1)
                    continue

                pbar.set_description(f"Benchmarking {name} (N={size})")
                
                run_creation_times, run_update_times, run_verifier_times, run_proof_sizes = [], [], [], []
                # NOTE: `prover_time` (for proof generation) is measured below but not stored in the final results.
                # The final result's 'prover_time' is actually the creation time.
                run_prover_times = []

                for i in range(num_runs):
                    initial_state = generate_random_state(size)
                    
                    scheme = scheme_class(initial_state)
                    creation_start_time = time.perf_counter()
                    scheme.create()
                    creation_time = time.perf_counter() - creation_start_time
                    run_creation_times.append(creation_time)

                    num_updates = min(FIXED_UPDATES, size)
                    if num_updates > 0:
                        elements_to_update = random.sample(list(scheme.state), num_updates)
                        
                        if isinstance(scheme, RsaAccumulatorTrapdoored):
                            new_elements = [e + b'-updated' for e in elements_to_update]
                            
                            batch_update_start_time = time.perf_counter()
                            scheme.batch_update(additions=new_elements, deletions=elements_to_update)
                            total_batch_time = time.perf_counter() - batch_update_start_time
                            
                            avg_update_time = total_batch_time / num_updates
                            run_update_times.append(avg_update_time)
                        else:
                            total_update_time = 0.0
                            update_iterator = tqdm(zip(elements_to_update, [e + b'-updated' for e in elements_to_update]), total=num_updates, desc=f"Updating (run {i + 1}/{num_runs})", leave=False)
                            for old_element, new_element in update_iterator:
                                update_start_time = time.perf_counter()
                                scheme.update(old_element, new_element)
                                total_update_time += time.perf_counter() - update_start_time

                            avg_update_time = total_update_time / num_updates
                            run_update_times.append(avg_update_time)
                    else:
                        run_update_times.append(0)

                    element_to_prove = random.choice(scheme.state) if scheme.state else generate_random_state(1)[0]
                    
                    prove_start_time = time.perf_counter()
                    proof = scheme.prove_membership(element_to_prove)
                    prover_time = time.perf_counter() - prove_start_time
                    run_prover_times.append(prover_time)
                    
                    verify_start_time = time.perf_counter()
                    is_valid = False
                    if proof is not None:
                        is_valid = scheme.verify_membership(element_to_prove, proof)
                    verifier_time = time.perf_counter() - verify_start_time

                    if not is_valid and "Verkle" not in name:
                         print(f"WARNING: Verification failed for {name} with state size {size}")

                    run_verifier_times.append(verifier_time)
                    
                    proof_size = scheme.get_proof_size(proof)
                    run_proof_sizes.append(proof_size)

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