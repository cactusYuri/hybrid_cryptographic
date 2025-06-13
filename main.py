import sys
import os

# Add the project root to the Python path
# This allows us to import modules from subdirectories
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from benchmarking.runner import run_benchmark
from benchmarking.plotter import plot_results

def main():
    """
    Main entry point for the experiment.
    """
    print("Starting blockchain accumulator benchmark...")
    
    # Run the benchmarks
    results = run_benchmark()
    
    print("\nBenchmark finished. Generating plots...")
    
    # Plot the results
    plot_results(results)
    
    print("\nPlots saved to 'experiment/' directory.")
    print("Experiment complete.")

if __name__ == "__main__":
    main()
