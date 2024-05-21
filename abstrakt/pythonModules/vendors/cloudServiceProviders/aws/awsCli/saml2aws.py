import subprocess
import os
import configparser
from pathlib import Path


def check_and_update_aws_credentials():
  # Define the path to the AWS credentials file
  credentials_path = Path.home() / '.aws' / 'credentials'

  def credentials_are_valid():
    # Check if the credentials are still valid by attempting to list S3 buckets (or other simple AWS command)
    try:
      result = subprocess.run(['aws', 'account', 'get-contact-information'], capture_output=True, text=True)
      return result.returncode == 0
    except Exception as e:
      print(f"Error checking credentials: {e}")
      return False

  def refresh_credentials():
    # Refresh credentials using saml2aws
    try:
      subprocess.run(['saml2aws', 'login'], check=True)
    except subprocess.CalledProcessError as e:
      print(f"Failed to refresh credentials using saml2aws: {e}")
      return False
    return True

  def load_and_export_credentials():
    # Load credentials from the file and export them as environment variables
    config = configparser.ConfigParser()
    config.read(credentials_path)

    if 'saml' in config:
      try:
        os.environ['AWS_ACCESS_KEY_ID'] = config['saml'].get('aws_access_key_id')
        os.environ['AWS_SECRET_ACCESS_KEY'] = config['saml'].get('aws_secret_access_key')
        os.environ['AWS_SESSION_TOKEN'] = config['saml'].get('aws_session_token')
        return True
      except Exception as e:
        print(f'Error: {e}')
    elif 'default' in config:
      try:
        os.environ['AWS_ACCESS_KEY_ID'] = config['default'].get('aws_access_key_id')
        os.environ['AWS_SECRET_ACCESS_KEY'] = config['default'].get('aws_secret_access_key')
        os.environ['AWS_SESSION_TOKEN'] = config['default'].get('aws_session_token')
        return True
      except Exception as e:
        print(f'Error: {e}')
    return False

  # Check if the current credentials are valid
  if credentials_are_valid():
    if load_and_export_credentials():
      print('Credentials successfully exported to environment variables.')
    else:
      print('Credentials could not be exported to environment variables.')
  else:
    print("Credentials are invalid or expired. Attempting to refresh...")
    if not refresh_credentials():
      print("Failed to obtain new credentials.")
      return  # Exit if we can't refresh credentials

    if not credentials_are_valid():
      print("New credentials are still not valid.")
      return  # Exit if new credentials are not valid

  # Load and export credentials
  if not load_and_export_credentials():
    print("Failed to load or export new credentials. Trying to authenticate using saml2aws.")
    if refresh_credentials():
      if not load_and_export_credentials():
        print("Failed to load or export new credentials.")
      else:
        return
    else:
      print("Failed to obtain new credentials.")
      return  # Exit if we can't refresh credentials

  print("SAML credentials are valid and exported as environment variables.")


# Usage
# check_and_update_aws_credentials()
