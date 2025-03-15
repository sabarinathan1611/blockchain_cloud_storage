import sqlite3
import os
import shutil
from Encryption.dataencryption import AESCipher as aes_cipher
from app import scheduler

def delete_user_files_and_data():
    # Absolute path to the SQLite database file
    db_path = os.path.abspath('./instance/database.db')

    # Check if the database file exists
    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}")
        return 404

    # Connect to the SQLite database
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA busy_timeout = 30000")  # Wait up to 30 seconds if the database is locked
        cursor = conn.cursor()

        try:
            # Get the user IDs from delete_account where deleted is False
            cursor.execute("SELECT user_id FROM delete_account WHERE deleted = 0")
            users_to_delete = cursor.fetchall()
            
            # Extract user IDs from the query result
            user_ids = [user[0] for user in users_to_delete]
            
            for user_id in user_ids:
                # Load user data from User table
                cursor.execute("SELECT username, email, path FROM User WHERE id = ?", (user_id,))
                user = cursor.fetchone()
                
                if user:
                    username, email, user_folder_path = user
                    # Print user details
                    print(f"User: {aes_cipher.decrypt_data(username)}, Email: {aes_cipher.decrypt_data(email)}, Folder: {aes_cipher.decrypt_data(user_folder_path)}")

                    # Load and delete related files
                    cursor.execute("SELECT id, filepath, private_key_path, public_key_path FROM File WHERE user_id = ?", (user_id,))
                    files = cursor.fetchall()

                    for file in files:
                        file_id, filepath, private_key_path, public_key_path = file
                        try:
                            # Decrypt and print file details
                            decrypted_filepath = aes_cipher.decrypt_data(filepath)
                            decrypted_private_key_path = aes_cipher.decrypt_data(private_key_path)
                            decrypted_public_key_path = aes_cipher.decrypt_data(public_key_path)
                            print(f"Deleting file: {decrypted_filepath}")

                            if os.path.exists(decrypted_private_key_path):
                                os.remove(decrypted_private_key_path)
                            else:
                                print(f"File not found: {decrypted_private_key_path}")

                            if os.path.exists(decrypted_public_key_path):
                                os.remove(decrypted_public_key_path)
                            else:
                                print(f"File not found: {decrypted_public_key_path}")

                            if os.path.exists(decrypted_filepath):
                                os.remove(decrypted_filepath)
                            else:
                                print(f"File not found: {decrypted_filepath}")
                        except Exception as e:
                            print(f"Error deleting file {file_id}: {e}")

                    # Load and delete related texts
                    cursor.execute("SELECT id, private_key_path, public_key_path FROM Text WHERE user_id = ?", (user_id,))
                    texts = cursor.fetchall()
                    for text in texts:
                        text_id, private_key_path, public_key_path = text
                        try:
                            # Decrypt and delete text keys
                            decrypted_private_key_path = aes_cipher.decrypt_data(private_key_path)
                            decrypted_public_key_path = aes_cipher.decrypt_data(public_key_path)

                            if os.path.exists(decrypted_private_key_path):
                                os.remove(decrypted_private_key_path)
                            else:
                                print(f"File not found: {decrypted_private_key_path}")

                            if os.path.exists(decrypted_public_key_path):
                                os.remove(decrypted_public_key_path)
                            else:
                                print(f"File not found: {decrypted_public_key_path}")
                        except Exception as e:
                            print(f"Error deleting text keys for text ID {text_id}: {e}")

                    # Delete the user and associated data from the database
                    cursor.execute("DELETE FROM File WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM Text WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM User WHERE id = ?", (user_id,))
                    conn.commit()

                    # Delete the user folder
                    try:
                        if os.path.exists(user_folder_path):
                            shutil.rmtree(user_folder_path)
                            print(f"Deleted folder: {user_folder_path}")
                        else:
                            print(f"Folder not found: {user_folder_path}")
                    except Exception as e:
                        print(f"Error deleting folder {user_folder_path}: {e}")

                    # Delete folders in uploads, private_key, and public_key directories
                    user_specific_dirs = [
                        os.path.join('./app/static/uploads', str(user_folder_path)),
                        os.path.join('./app/static/key/private_key', str(user_folder_path)),
                        os.path.join('./app/static/key/public_key', str(user_folder_path))
                    ]
                    
                    for dir_path in user_specific_dirs:
                        try:
                            if os.path.exists(dir_path):
                                shutil.rmtree(dir_path)
                                print(f"Deleted directory: {dir_path}")
                            else:
                                print(f"Directory not found: {dir_path}")
                        except Exception as e:
                            print(f"Error deleting directory {dir_path}: {e}")

                else:
                    print(f"User with ID {user_id} not found")

            # Update delete_account table to set deleted to True
            cursor.executemany("UPDATE delete_account SET deleted = 1 WHERE user_id = ?", [(user_id,) for user_id in user_ids])
            conn.commit()

            print("Processing completed.")
            return 200

        except Exception as e:
            print(f"Error: {e}")
            conn.rollback()
            return 500

        finally:
            conn.close()

    except sqlite3.OperationalError as e:
        print(f"Database connection failed: {e}")
        return 500
#scheduler.add_job(id='minute_task', func=delete_user_files_and_data, trigger='interval', minutes=2)
scheduler.add_job(id='daily_task', func=delete_user_files_and_data, trigger='cron', hour=0, minute=0)