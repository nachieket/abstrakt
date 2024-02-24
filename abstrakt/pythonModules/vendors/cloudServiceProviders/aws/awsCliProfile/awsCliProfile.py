import subprocess
import configparser
import os
from datetime import datetime
# from typing import Dict, Optional


class AWSCliProfile:
  @staticmethod
  def get_existing_profiles():
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

  @staticmethod
  def validate_profile_credentials(profile, config):
    access_key_id = config.get(profile, "aws_access_key_id", fallback=None)
    secret_access_key = config.get(profile, "aws_secret_access_key", fallback=None)

    if not access_key_id or len(access_key_id) != 20:
      print(f"{profile} profile has an invalid aws_access_key_id.\n")
      return False

    if not secret_access_key or len(secret_access_key) != 40:
      print(f"{profile} profile has an invalid aws_secret_access_key.\n")
      return False

    return True

  def validate_saml_profile(self, config):
    """
    Validates the provided SAML profile configuration.

    Args:
      config (dict): The configuration dictionary containing SAML profile details.

    Returns:
      True if the SAML profile is valid, False otherwise.
    """

    # Check if base profile credentials are valid first.
    if not self.validate_profile_credentials("saml", config):
      return False

    # Ensure required SAML-specific configuration values are present.
    required_keys = ["aws_session_token", "aws_security_token", "x_principal_arn"]

    missing_keys = [key for key in required_keys if config.get("saml", key, fallback=None) is None]

    if missing_keys:
      print(f"saml profile is missing required keys: {', '.join(missing_keys)}.\n")
      return False

    # Validate the expiry of the security token.
    expiry_str = config.get("saml", "x_security_token_expires", fallback=None)

    if not expiry_str:
      print("saml profile is missing the 'x_security_token_expires' value.\n")
      return False

    try:
      expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
      print(f"Invalid format for 'x_security_token_expires': {expiry_str}.\n")
      return False

    now = datetime.now(expiry.tzinfo)
    if now >= expiry:
      print(f"\nsaml profile's 'x_security_token_expires' value is expired.\n")
      return False

    # All checks passed, profile is valid.
    return True

  @staticmethod
  def configure_static_credentials(profile_name) -> bool:
    """
    Configures an AWS profile with user-provided credentials and settings.

    Args:
      profile_name (str, optional): The name of the AWS profile to configure (default: "default").

    Returns:
      True if configuration is successful, False otherwise.
    """

    print(f"Please provide your AWS configuration details for profile '{profile_name}':\n")

    aws_access_key = input("AWS Access Key ID: ")

    # Validate key length instead of hardcoding specific values
    while len(aws_access_key) != 20:
      print(f"Invalid key length. {profile_name} access key should be 20 characters. Try again.")
      aws_access_key = input("AWS Access Key ID: ")

    aws_secret_key = input("AWS Secret Access Key: ")

    while len(aws_secret_key) != 40:
      print(f"Invalid key length. {profile_name} secret key should be 40 characters. Try again.")
      aws_secret_key = input("AWS Secret Access Key: ")

    default_region = input("Default region name (default - eu-west-2): ")

    if default_region == "":
      default_region = "eu-west-2"

    default_output = input("Default output format [json, text, or yaml] (default - json): ")

    if default_output == "":
      default_output = "json"

    try:
      # Use f-strings for clearer command construction
      # aws_command = f"aws configure set --profile {profile_name}"

      subprocess.run(f"aws configure set --profile {profile_name} aws_access_key_id {aws_access_key}", shell=True)
      subprocess.run(f"aws configure set --profile {profile_name} aws_secret_access_key {aws_secret_key}", shell=True)
      subprocess.run(f"aws configure set --profile {profile_name} region {default_region}", shell=True)
      subprocess.run(f"aws configure set --profile {profile_name} output {default_output}", shell=True)

      print(f"AWS profile '{profile_name}' configuration complete.\n")
      return True
    except Exception as e:
      print(f"An error occurred while configuring AWS profile '{profile_name}': {e}. Exiting the program.")
      return False

  @staticmethod
  def configure_saml2aws(idp_url, profile_name) -> bool:
    try:
      # Check if the saml2aws configuration file exists
      config_file = os.path.expanduser("~/.saml2aws")

      if not os.path.exists(config_file):
        print("SAML2AWS configuration not found. Configuring...")

        # Run the saml2aws configure command to set up configurations
        configure_command = f"saml2aws configure --url={idp_url} --profile={profile_name}"
        subprocess.run(configure_command, shell=True, check=True)

        print("SAML2AWS configuration completed.")

      # Run the saml2aws login command
      login_command = f"saml2aws login --profile={profile_name}"
      process = subprocess.Popen(login_command, shell=True)

      process.communicate()

      if process.returncode == 0:
        print("SAML authentication successful")
        return True
      else:
        print("SAML authentication failed")
        return False
    except Exception as e:
      print(f"An error occurred: {str(e)}")
      return False

  def configure_aws_profile(self, idp_url=None) -> bool:
    while True:
      method = input('Select the method to configure AWS credentials [static/saml2aws]: ')

      if method == 'static':
        # profile_name = input('Enter profile name [default]: ')
        # profile_name = profile_name or 'default'
        return self.configure_static_credentials(profile_name='default')
      elif method == 'saml2aws':
        print('This method is currently not supported. Exiting the program.\n')
        exit()
        # idp_url = idp_url or input('Enter IDP URL: ')
        # profile_name = input('Enter profile name [default]: ')
        # profile_name = profile_name or 'default'
        # return self.configure_saml2aws(idp_url=idp_url, profile_name='saml')
      else:
        print('Incorrect method. Try again.')

  def ensure_valid_aws_profile(self) -> bool:
    """
    Checks for a valid AWS profile and configures one if necessary.

    Returns True if a valid profile is found or created, False otherwise.
    """
    existing_profiles, config = self.get_existing_profiles()

    if not existing_profiles:
      print("No existing AWS profile found.\n")
      answer = input("Do you want to configure an AWS profile? (y/n): ")

      if answer == "y":
        if self.configure_aws_profile():
          return True
        else:
          print("Failed to configure profile. Exiting.\n")
          exit()
      else:
        print("Exiting as no valid profile was found.\n")
        exit()

    saml_valid = self.validate_saml_profile(config) if "saml" in existing_profiles else False
    default_valid = self.validate_profile_credentials("default", config) if "default" in existing_profiles else False

    if saml_valid and not default_valid:
      print("Using valid SAML profile.")
      return True
    elif default_valid and not saml_valid:
      print("Using valid default profile.\n")
      return True
    elif default_valid and saml_valid:
      print("Both SAML and default profiles are valid. Choosing default profile.\n")
      return True
    else:
      print("Neither SAML nor default profile is valid.\n")
      answer = input("Do you want to configure an AWS profile? (y/n): ")

      if answer == "y":
        if self.configure_aws_profile():
          return True
        else:
          print("Failed to configure profile. Exiting.\n")
          exit()
      else:
        print("Exiting as no valid profile was found.\n")
        exit()

  # def validate_saml_profile(self, config):
  #   if not self.validate_profile_credentials("saml", config):
  #     return False
  #
  #   session_token = config.get("saml", "aws_session_token", fallback=None)
  #   security_token = config.get("saml", "aws_security_token", fallback=None)
  #   principal_arn = config.get("saml", "x_principal_arn", fallback=None)
  #
  #   if not session_token or not security_token or not principal_arn:
  #     print("saml profile has missing values for aws_session_token, aws_security_token, or x_principal_arn.\n")
  #     return False
  #
  #   expiry_str = config.get("saml", "x_security_token_expires", fallback=None)
  #   if not expiry_str:
  #     print("saml profile has a missing x_security_token_expires value.\n")
  #     return False
  #
  #   expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S%z")
  #   now = datetime.now(expiry.tzinfo)
  #
  #   if now >= expiry:
  #     print("\n\nsaml profile has an expired x_security_token_expires value.\n")
  #     return False
  #
  #   return True

  # @staticmethod
  # def configure_aws_profile():
  #   print("Please provide your AWS configuration details:\n")
  #   aws_access_key = input("AWS Access Key ID: ")
  #
  #   while len(aws_access_key) != 20:
  #     print('This is not a valid aws access key, as the length is not 20. Try again.')
  #     aws_access_key = input("AWS Access Key ID: ")
  #
  #   aws_secret_key = input("AWS Secret Access Key: ")
  #
  #   while len(aws_secret_key) != 40:
  #     print('This is not a valid aws access key, as the length is not 40. Try again.')
  #     aws_secret_key = input("AWS Secret Key ID: ")
  #
  #   default_region = input("Default region name (default - eu-west-2): ")
  #
  #   if default_region == '':
  #     default_region = 'eu-west-2'
  #
  #   default_output = input("Default output format [json, text, or yaml] (default - json): ")
  #
  #   if default_output == '':
  #     default_output = 'json'
  #
  #   try:
  #     aws_command = ["aws", "configure", "set"]
  #
  #     subprocess.run(aws_command + ["aws_access_key_id", aws_access_key])
  #     subprocess.run(aws_command + ["aws_secret_access_key", aws_secret_key])
  #     subprocess.run(aws_command + ["region", default_region])
  #     subprocess.run(aws_command + ["output", default_output])
  #
  #     print("AWS configuration complete.\n")
  #
  #     return True
  #   except Exception as e:
  #     print(f"An error occurred while configuring AWS: {e}. Exiting the program.")
  #     exit()

  # def check_aws_profile(self):
  #   existing_profiles, config = self.find_existing_profiles()
  #
  #   if not existing_profiles:
  #     print("Neither saml nor default profile exists.")
  #
  #     answer = None
  #
  #     while answer != 'y' or answer != 'n':
  #       answer = input('No valid profile exists. Do you want to configure one? (y/n): ')
  #
  #       if answer == 'y':
  #         if self.configure_aws_profile():
  #           return True
  #         else:
  #           return False
  #       elif answer == 'n':
  #         print('This program cannot continue with an aws credentials and profile. Exiting the program.\n')
  #         exit()
  #   else:
  #     saml_valid = None
  #     default_valid = None
  #
  #     if "saml" in existing_profiles:
  #       saml_valid = self.validate_saml_profile(config)
  #
  #     if "default" in existing_profiles:
  #       default_valid = self.validate_profile_credentials("default", config)
  #
  #     if saml_valid and not default_valid:
  #       print('there is no default profile but a valid saml profile exists.')
  #       print('continuing the program execution with saml profile...\n')
  #       return True
  #     elif default_valid and not saml_valid:
  #       print('there is a default profile but no valid saml profile exists.\n')
  #       print('continuing the program execution with default profile...\n')
  #       return True
  #     elif default_valid and saml_valid:
  #       print('both default and saml profiles are valid')
  #       print('continuing the program execution...\n')
  #       return True
  #     else:
  #       answer = None
  #
  #       while answer != 'y' or answer != 'n':
  #         answer = input('No valid profile exists. Do you want to configure one? (y/n): ')
  #
  #         if answer == 'y':
  #           if self.configure_aws_profile():
  #             return True
  #           else:
  #             return False
  #         elif answer == 'n':
  #           print('This program cannot continue with an aws credentials and profile. Exiting the program.\n')
  #           exit()
