import subprocess
import configparser
import yaml
import os
# from datetime import datetime
# from typing import Dict, Optional


class AWSOps:
  @staticmethod
  def check_credentials_validity():
    # Check if the credentials are still valid by attempting to list S3 buckets (or other simple AWS command)
    try:
      result = subprocess.run(['aws', 'account', 'get-contact-information'], capture_output=True, text=True)
      if result.returncode == 0:
        return True
      else:
        return False
    except Exception as e:
      print(f"Error checking credentials: {e}")
      return False

  @staticmethod
  def get_existing_profiles() -> tuple:
    credentials_file = os.path.expanduser("~/.aws/credentials")

    if not os.path.exists(credentials_file):
      print(f"Credentials file '{credentials_file}' not found. Creating a new one.\n")

      with open(credentials_file, 'w') as _:
        pass

    config = configparser.ConfigParser()
    config.read(credentials_file)

    existing_profiles = []

    if config.has_section("saml"):
      existing_profiles.append("saml")

    if config.has_section("default"):
      existing_profiles.append("default")

    return existing_profiles, config

  def configure_aws_profile(self, exists) -> bool:
    while True:
      method = input('Select the method to configure AWS credentials [static/saml2aws]: ')
      print(self)

      if method == 'static':
        if self.configure_static_credentials():
          os.environ['AWS_PROFILE'] = 'default'

          if self.check_credentials_validity():
            return True

        print('Configured aws credentials are not valid.\n')
        return False
      elif method == 'saml2aws' or method == '':
        if exists == 'yes':
          if self.configure_saml2aws():
            if self.saml2aws_login():
              os.environ['AWS_PROFILE'] = 'saml'

              if self.check_credentials_validity():
                return True

          print('Configured aws credentials are not valid.\n')
          return False
        else:
          if self.saml2aws_login():
            os.environ['AWS_PROFILE'] = 'saml'

            if self.check_credentials_validity():
              return True

        print('Configured aws credentials are not valid.\n')
        return False
      else:
        print('Incorrect method. Try again.')
        return False

  @staticmethod
  def configure_static_credentials() -> bool:
    """
    Configures an AWS profile with user-provided credentials and settings.

    Returns:
      True if configuration is successful, False otherwise.
    """

    print(f"Please provide your AWS configuration details for profile 'default':\n")

    aws_access_key = input("AWS Access Key ID: ")

    while len(aws_access_key) != 20:
      print(f"Invalid key length. default profile access key should be 20 characters. Try again.")
      aws_access_key = input("AWS Access Key ID: ")

    aws_secret_key = input("AWS Secret Access Key: ")

    while len(aws_secret_key) != 40:
      print(f"Invalid key length. default profile secret key should be 40 characters. Try again.")
      aws_secret_key = input("AWS Secret Access Key: ")

    default_region = input("Default region name (default - eu-west-2): ")

    if default_region == "":
      default_region = "eu-west-2"

    default_output = input("Default output format [json, text, or yaml] (default - json): ")

    if default_output == "":
      default_output = "json"

    try:
      subprocess.run(f"aws configure set --profile default aws_access_key_id {aws_access_key}", shell=True)
      subprocess.run(f"aws configure set --profile default aws_secret_access_key {aws_secret_key}", shell=True)
      subprocess.run(f"aws configure set --profile default region {default_region}", shell=True)
      subprocess.run(f"aws configure set --profile default output {default_output}", shell=True)

      print(f"AWS profile 'default' configuration complete.\n")
      return True
    except Exception as e:
      print(f"An error occurred while configuring AWS profile 'default': {e}. Exiting the program.")
      return False

  @staticmethod
  def configure_saml2aws():
    try:
      subprocess.run(['saml2aws', 'configure'], check=True)
      return True
    except subprocess.CalledProcessError as e:
      print(f"Failed to refresh credentials using saml2aws: {e}")
      return False

  @staticmethod
  def is_saml2aws_profile_configured(profile_name='default'):
    config_path = os.path.expanduser('~/.saml2aws')

    # Check if the configuration file exists
    if not os.path.exists(config_path):
      print(f"Configuration file '{config_path}' does not exist.")
      return False

    # Read the configuration file
    with open(config_path, 'r') as config_file:
      try:
        config = yaml.safe_load(config_file)
      except yaml.YAMLError as e:
        print(f"Error reading YAML file: {e}")
        return False

    # Check if the profile exists in the configuration
    profiles = config.get('profiles', [])
    for profile in profiles:
      if profile.get('name') == profile_name:
        if (profile.get('url') and profile.get('username') and profile.get('provider') and profile.get('mfa') and
                profile.get('aws_urn') and profile.get('aws_profile')):
          print(f"The saml2aws Profile '{profile_name}' is configured.")
        return True

    print(f"Profile 'The saml2aws {profile_name}' is not configured.")
    return False

  @staticmethod
  def saml2aws_login():
    try:
      subprocess.run(['saml2aws', 'login'], check=True)
      return True
    except subprocess.CalledProcessError as e:
      print(f"Failed to refresh credentials using saml2aws: {e}")
      return False

  def check_aws_login(self) -> bool:
    existing_profiles, config = self.get_existing_profiles()

    if existing_profiles:
      for profile in existing_profiles:
        os.environ['AWS_PROFILE'] = profile

        if self.check_credentials_validity():
          print(f'Profile {profile} has valid aws credentials\n')
          return True
        else:
          print(f'Profile {profile} does not have valid aws credentials\n')

      print("No valid AWS profile found.\n")
      answer = input("Do you want to configure an AWS profile? (y/n): ")
      print(self)

      if answer.lower() == "y":
        if self.configure_aws_profile(exists='no'):
          print('Successfully configured aws profile.\n')
          return True
        else:
          print("Failed to configure aws profile. Exiting.\n")
          exit()
      else:
        print("Exiting as no valid profile was found.\n")
        exit()
    else:
      print("No existing AWS profile found.\n")
      answer = input("Do you want to configure an AWS profile? (y/n): ")
      print(self)

      if answer.lower() == "y":
        if self.configure_aws_profile(exists='yes'):
          print('Successfully configured aws profile.\n')
          return True
        else:
          print("Failed to configure aws profile. Exiting.\n")
          exit()
      else:
        print("Exiting as no valid profile was found.\n")
        exit()
