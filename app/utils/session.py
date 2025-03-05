import logging
from Cornjob.DeleteTask import delete_user_files_and_data
from . import scheduler
import  json

# Schedule the task to delete files
scheduler.add_job(id='daily_task', func=delete_user_files_and_data, trigger='cron', hour=0, minute=0)

def dict_to_string(input_dict):
    """
    Convert a dictionary to a JSON string.
    """
    return json.dumps(input_dict)

def string_to_dict(input_string):
    """
    Convert a JSON string back to a dictionary.
    """
    return json.loads(input_string)
