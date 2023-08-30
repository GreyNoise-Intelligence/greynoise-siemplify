from constants import USER_AGENT
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Execute GNQL Query"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    api_key = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="GN API Key")

    session = GreyNoise(api_key=api_key, integration_name=USER_AGENT)

    query = siemplify.extract_action_param(param_name="query", print_value=True)
    limit = siemplify.extract_action_param(param_name="limit", default_value="10", is_mandatory=False, print_value=True)

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}

    siemplify.LOGGER.info("Running GreyNoise Query: {}".format(query))
    try:
        res = session.query(query=query, size=limit)
        output = res
        siemplify.result.add_json("query_result", output)
        output_json["query_result"] = output
        total = output["count"]
        output_message = "Successfully ran query: {} - Total Results: {} - " "Returned Results: {},".format(
            query, total, limit
        )

    except RequestFailure as e:
        if "401" in str(e):
            siemplify.LOGGER.info("Unable to auth, please check API Key")
            output_message = "Unable to auth, please check API Key"
        else:
            siemplify.LOGGER.error("There was an issue with your query: {}".format(e))
            output_message = "There was an issue with your query: {}".format(e)
        result_value = False
        status = EXECUTION_STATE_FAILED

    except RateLimitError:
        siemplify.LOGGER.info("Daily rate limit reached, please check API Key")
        output_message = "Daily rate limit reached, please check API Key"
        result_value = False
        status = EXECUTION_STATE_FAILED

    except Exception as e:
        siemplify.LOGGER.info(e)
        siemplify.LOGGER.info("Unknown Error Occurred")
        output_message = "Unknown Error Occurred"
        result_value = False
        status = EXECUTION_STATE_FAILED

    if output_json:
        siemplify.result.add_result_json({"results": convert_dict_to_json_result_dict(output_json)})

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
