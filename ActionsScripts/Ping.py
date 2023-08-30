from constants import USER_AGENT
from datetime import datetime
from greynoise import GreyNoise
from greynoise.exceptions import RequestFailure
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Ping"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    api_key = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="GN API Key")

    session = GreyNoise(api_key=api_key, integration_name=USER_AGENT)
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    try:
        res = session.test_connection()
        expires = datetime.strptime(res["expiration"], "%Y-%m-%d")
        now = datetime.today()
        if res["offering"] != "community" and expires > now:
            # is valid enterprise api key
            siemplify.LOGGER.info("Connectivity Response: {}".format(res))
            output_message = "Successful Connection"
        elif res["offering"] != "community" and expires < now:
            # is expired enterprise api key
            siemplify.LOGGER.info("Unable to auth, API Key appears to be expired")
            output_message = "Unable to auth, API Key appears to be expired"
            result_value = False
            status = EXECUTION_STATE_FAILED
        else:
            # is a community api key
            siemplify.LOGGER.info("Connectivity Response: {}".format(res))
            output_message = "Successful Connection"

    except RequestFailure:
        siemplify.LOGGER.info("Unable to auth, please check API Key")
        output_message = "Unable to auth, please check API Key"
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
