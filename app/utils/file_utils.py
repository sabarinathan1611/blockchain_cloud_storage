import uuid
import os
import json
from flask import current_app as app

def generate_filename(file_type):
    """
    Generate a unique filename.
    """
    extensions = {'der': '.der', 'file': ''}
    return str(uuid.uuid4()) + extensions.get(file_type, '')

def get_folder_size(folder_path):
    """
    Calculate the total folder size in GB.
    """
    total_size = sum(
        os.path.getsize(os.path.join(dirpath, file))
        for dirpath, _, filenames in os.walk(folder_path)
        for file in filenames
    )
    return total_size / (1024 ** 3)  # Convert bytes to GB

def makedir():
    """
    Create required directories dynamically.
    """
    uuid_str = str(uuid.uuid4())
    base_path = os.path.dirname(os.path.abspath(__file__))
    paths = {
        'private_key': f'static/key/private_key/{uuid_str}',
        'public_key': f'static/key/public_key/{uuid_str}',
        'uploads': f'static/uploads/{uuid_str}',
        'decrypt': f'static/Decrypt/{uuid_str}'
    }

    for key, path in paths.items():
        full_path = os.path.join(base_path, path)
        os.makedirs(full_path, exist_ok=True)

    return uuid_str
