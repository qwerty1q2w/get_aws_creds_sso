#!/usr/bin/env python3

# before run this script you must install some libs use next command:
# pip3 install selenium selenium-wire

import json
import os
import urllib.parse
import subprocess
from seleniumwire import webdriver

url = "https://sso.yourcompany.com/auth/realms/yourrealm/protocol/saml/clients/amazon-aws"
sso_provider = "sso.yourcompany.com" 

def get_aws_temp_session():
    driver = webdriver.Chrome()
    driver.get(url)

    # Wait for the user to perform 2FA and role selection manually
    input(
        "Please perform 2FA and role selection manually, wait when aws main page complete load and then press 'Enter' here..."
    )

    for request in driver.requests:
        if request.response:
            try:
                if (
                    json.loads(request.body.decode("utf-8"))["batchRequest"][0][
                        "eventType"
                    ]
                    == "clogLoad"
                ):
                    resp = json.loads(request.body.decode("utf-8"))["awsUserInfo"]
                    arn = json.loads(resp)["arn"]
                    account_id = arn.split(":")[4]
                    role = arn.split("/")[1]
            except Exception:
                pass
            if "SAMLResponse" in request.body.decode(
                "utf-8"
            ) and "RelayState" not in request.body.decode("utf-8"):
                saml_encoded = request.body.decode("utf-8").split("=")[1]
                saml_decoded = urllib.parse.unquote(saml_encoded)
    driver.quit()
    return saml_decoded, account_id, role


def get_aws_creds(file_session, account_id, role):
    command = [
        "/usr/local/bin/aws",
        "sts",
        "assume-role-with-saml",
        "--role-arn",
        f"arn:aws:iam::{account_id}:role/{role}",
        "--principal-arn",
        f"arn:aws:iam::{account_id}:saml-provider/{sso_provider}",
        "--saml-assertion",
        f"file://{file_session}",
        "--output",
        "json",
    ]
    try:
        result = subprocess.run(
            command,
            # shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        command_response = result.stdout.decode().strip()
        command_response_json = json.loads(command_response)
    except Exception as e:
        print("An error occurred:", e)
        exit(1)

    aws_access_key_id = command_response_json["Credentials"]["AccessKeyId"]
    aws_secret_access_key = command_response_json["Credentials"]["SecretAccessKey"]
    aws_session_token = command_response_json["Credentials"]["SessionToken"]

    data = f"""[SAML-PROFILE]
aws_access_key_id = {aws_access_key_id}
aws_secret_access_key = {aws_secret_access_key}
aws_session_token = {aws_session_token}
"""

    return data


def main():
    temp_session = "samlresponse"
    # Get SAMLResponse and AWS account details
    saml_decoded, account_id, role = get_aws_temp_session()

    # Write SAMLResponse to file in current directory
    try:
        with open(temp_session, "w") as file:
            file.write(saml_decoded)
    except Exception as e:
        print("An error occurred:", e)
        exit(1)

    # Get AWS credentials
    profile_details = get_aws_creds(temp_session, account_id, role)
    # Remove SAMLResponse file - because it not needed anymore
    os.remove(temp_session)

    # Write AWS credentials to file
    home = os.path.expanduser("~")
    file_path = os.path.join(home, ".aws/credentials")
    try:
        with open(file_path, "w") as file:
            file.write(profile_details)
        print(f"File '{file_path}' has been created.")
    except Exception as e:
        print("An error occurred:", e)
        exit(1)


if __name__ == "__main__":
    main()
