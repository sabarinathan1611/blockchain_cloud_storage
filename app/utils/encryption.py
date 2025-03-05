from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
import json
def string_to_hex(input_string):
    """
    Convert a string to a hex-encoded binary.
    """
    return b64encode(input_string.encode())

def hex_to_string(input_hex):
    """
    Convert a hex-encoded binary back to a string.
    """
    return b64decode(input_hex).decode()


def dict_to_string(input_dict):
    """
    Convert a dictionary to a string.
    
    Args:
        input_dict (dict): The dictionary to be converted.
    
    Returns:
        str: The converted string.
    """
    return json.dumps(input_dict)

def string_to_dict(input_string):
    """
    Convert a string to a dictionary.
    
    Args:
        input_string (str): The string to be converted.
    
    Returns:
        dict: The converted dictionary.
    """
    return json.loads(input_string)
