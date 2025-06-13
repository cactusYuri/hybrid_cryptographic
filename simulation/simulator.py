import os

def generate_random_state(size: int) -> list[bytes]:
    """
    Generates a list of unique random byte strings to simulate a blockchain state.
    
    :param size: The number of elements in the state.
    :return: A list of byte strings.
    """
    return [os.urandom(32) for _ in range(size)] 