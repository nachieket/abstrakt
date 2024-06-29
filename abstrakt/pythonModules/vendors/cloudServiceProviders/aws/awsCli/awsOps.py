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
      print()

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
      print()

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
      print()

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

  # @staticmethod
  # def validate_profile_credentials(profile, config):
  #   access_key_id = config.get(profile, "aws_access_key_id", fallback=None)
  #   secret_access_key = config.get(profile, "aws_secret_access_key", fallback=None)
  #
  #   if not access_key_id or len(access_key_id) != 20:
  #     print(f"{profile} profile has an invalid aws_access_key_id.\n")
  #     return False
  #
  #   if not secret_access_key or len(secret_access_key) != 40:
  #     print(f"{profile} profile has an invalid aws_secret_access_key.\n")
  #     return False
  #
  #   return True

  # def validate_saml_profile(self, config):
  #   """
  #   Validates the provided SAML profile configuration.
  #
  #   Args:
  #     config (dict): The configuration dictionary containing SAML profile details.
  #
  #   Returns:
  #     True if the SAML profile is valid, False otherwise.
  #   """
  #
  #   # Check if base profile credentials are valid first.
  #   if not self.validate_profile_credentials("saml", config):
  #     return False
  #
  #   # Ensure required SAML-specific configuration values are present.
  #   required_keys = ["aws_session_token", "aws_security_token", "x_principal_arn"]
  #
  #   missing_keys = [key for key in required_keys if config.get("saml", key, fallback=None) is None]
  #
  #   if missing_keys:
  #     print(f"saml profile is missing required keys: {', '.join(missing_keys)}.\n")
  #     return False
  #
  #   # Validate the expiry of the security token.
  #   expiry_str = config.get("saml", "x_security_token_expires", fallback=None)
  #
  #   if not expiry_str:
  #     print("saml profile is missing the 'x_security_token_expires' value.\n")
  #     return False
  #
  #   try:
  #     expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S%z")
  #   except ValueError:
  #     print(f"Invalid format for 'x_security_token_expires': {expiry_str}.\n")
  #     return False
  #
  #   now = datetime.now(expiry.tzinfo)
  #   if now >= expiry:
  #     print(f"\nsaml profile's 'x_security_token_expires' value is expired.\n")
  #     return False
  #
  #   # All checks passed, profile is valid.
  #   return True

  # @staticmethod
  # def configure_saml2aws(idp_url, profile_name) -> bool:
  #   try:
  #     # Check if the saml2aws configuration file exists
  #     config_file = os.path.expanduser("~/.saml2aws")
  #
  #     if not os.path.exists(config_file):
  #       print("SAML2AWS configuration not found. Configuring...")
  #
  #       # Run the saml2aws configure command to set up configurations
  #       configure_command = f"saml2aws configure --url={idp_url} --profile={profile_name}"
  #       subprocess.run(configure_command, shell=True, check=True)
  #
  #       print("SAML2AWS configuration completed.")
  #
  #     # Run the saml2aws login command
  #     login_command = f"saml2aws login --profile={profile_name}"
  #     process = subprocess.Popen(login_command, shell=True)
  #
  #     process.communicate()
  #
  #     if process.returncode == 0:
  #       print("SAML authentication successful")
  #       return True
  #     else:
  #       print("SAML authentication failed")
  #       return False
  #   except Exception as e:
  #     print(f"An error occurred: {str(e)}")
  #     return False

  # def ensure_valid_aws_profile(self) -> bool:
  #   """
  #   Checks for a valid AWS profile and configures one if necessary.
  #
  #   Returns True if a valid profile is found or created, False otherwise.
  #   """
  #   existing_profiles, config = self.get_existing_profiles()
  #
  #   if not existing_profiles:
  #     print("No existing AWS profile found.\n")
  #     answer = input("Do you want to configure an AWS profile? (y/n): ")
  #     print()
  #
  #     if answer == "y":
  #       if self.configure_aws_profile():
  #         print('Successfully configured aws profile.\n')
  #       else:
  #         print("Failed to configure aws profile. Exiting.\n")
  #         exit()
  #     else:
  #       print("Exiting as no valid profile was found.\n")
  #       exit()
  #
  #   saml_valid = self.validate_saml_profile(config) if "saml" in existing_profiles else False
  #   default_valid = self.validate_profile_credentials("default", config) if "default" in existing_profiles else False
  #
  #   if saml_valid and not default_valid:
  #     print("Using valid SAML profile.")
  #     return True
  #   elif default_valid and not saml_valid:
  #     print("Using valid default profile.\n")
  #     return True
  #   elif default_valid and saml_valid:
  #     print("Both SAML and default profiles are valid. Choosing default profile.\n")
  #     return True
  #   else:
  #     print("Neither SAML nor default profile is valid.\n")
  #     answer = input("Do you want to configure an AWS profile? (y/n): ")
  #     print()
  #
  #     if answer == "y":
  #       if self.configure_aws_profile():
  #         return True
  #       else:
  #         print("Failed to configure profile. Exiting.\n")
  #         exit()
  #     else:
  #       print("Exiting as no valid profile was found.\n")
  #       exit()