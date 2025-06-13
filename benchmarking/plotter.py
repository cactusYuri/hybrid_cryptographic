import matplotlib.pyplot as plt
import numpy as np
from .metrics import ExperimentResults

def plot_results(results: ExperimentResults):
    """
    Generates and saves plots for the benchmark results.
    """
    schemes = list(results.keys())
    
    # --- Plot 1: Proof Size vs. State Size ---
    plt.figure(figsize=(10, 6))
    for scheme in schemes:
        state_sizes = [r.state_size for r in results[scheme]]
        proof_sizes = [r.proof_size for r in results[scheme]]
        plt.plot(state_sizes, proof_sizes, marker='o', linestyle='-', label=f"{scheme.capitalize()} Proof Size")
    
    plt.xlabel("Number of Elements in State (N)")
    plt.ylabel("Proof Size (bytes)")
    plt.title("Proof Size vs. State Size")
    plt.legend()
    plt.grid(True)
    plt.xscale('log') # State size often grows exponentially
    plt.yscale('log') # Proof size can also have log scaling
    plt.savefig("experiment/proof_size_vs_state_size.png")
    plt.show()

    # --- Plot 2: Prover Creation Time vs. State Size ---
    plt.figure(figsize=(10, 6))
    for scheme in schemes:
        state_sizes = [r.state_size for r in results[scheme]]
        prover_times = [r.prover_time for r in results[scheme]]
        plt.plot(state_sizes, prover_times, marker='o', linestyle='-', label=f"{scheme.capitalize()} Creation Time")

    plt.xlabel("Number of Elements in State (N)")
    plt.ylabel("Prover Creation Time (seconds)")
    plt.title("Prover Creation Time vs. State Size")
    plt.legend()
    plt.grid(True)
    plt.xscale('log')
    plt.yscale('log')
    plt.savefig("experiment/prover_creation_time_vs_state_size.png")
    plt.show()

    # --- Plot 3: Prover Update Time vs. State Size ---
    plt.figure(figsize=(10, 6))
    for scheme in schemes:
        state_sizes = [r.state_size for r in results[scheme]]
        update_times = [r.update_time for r in results[scheme]]
        plt.plot(state_sizes, update_times, marker='o', linestyle='-', label=f"{scheme.capitalize()} Update Time")

    plt.xlabel("Number of Elements in State (N)")
    plt.ylabel("Prover Update Time (seconds)")
    plt.title("Prover Update Time (for 10% state change) vs. State Size")
    plt.legend()
    plt.grid(True)
    plt.xscale('log')
    plt.yscale('log')
    plt.savefig("experiment/prover_update_time_vs_state_size.png")
    plt.show()

    # --- Plot 4: Verifier Time vs. State Size ---
    plt.figure(figsize=(10, 6))
    for scheme in schemes:
        state_sizes = [r.state_size for r in results[scheme]]
        verifier_times = [r.verifier_time for r in results[scheme]]
        plt.plot(state_sizes, verifier_times, marker='o', linestyle='-', label=f"{scheme.capitalize()} Verifier Time")

    plt.xlabel("Number of Elements in State (N)")
    plt.ylabel("Verifier Time (seconds)")
    plt.title("Verifier Time vs. State Size")
    plt.legend()
    plt.grid(True)
    plt.xscale('log')
    # plt.yscale('log') # Verifier time might be constant, log scale might not be best
    plt.savefig("experiment/verifier_time_vs_state_size.png")
    plt.show() 