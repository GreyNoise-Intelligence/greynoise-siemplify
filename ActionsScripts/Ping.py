import requests
from constants import USER_AGENT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    api_key = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME, param_name="GN API Key"
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "key": api_key,
        "User-Agent": USER_AGENT,
    }
    url = "https://api.greynoise.io/ping"

    res = requests.get(url, headers=headers)
    res.raise_for_status()

    if "ApiKey authenticate failed" in res.content.decode("utf-8"):
        raise Exception("Error, bad credentials")

    siemplify.end("Successful Connection", True)


if __name__ == "__main__":
    main()
