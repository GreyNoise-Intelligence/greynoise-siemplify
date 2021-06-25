import requests
from constants import USER_AGENT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Execute GNQL Query"


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

    query = siemplify.extract_action_param(param_name="query", print_value=True)
    limit = siemplify.extract_action_param(
        param_name="limit", default_value="10", is_mandatory=False, print_value=True
    )

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}

    siemplify.LOGGER.info("Running GreyNoise Query: {}".format(query))
    url = ("https://api.greynoise.io/v2/experimental/" "gnql?query={}&size={}").format(
        query, limit
    )

    res = requests.get(url, headers=headers)

    if res.status_code == 401:
        output_message = "Unable to auth, please check API Key.  This action requires a Paid Subscription."
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.end(output_message, result_value, status)

    output = res.json()

    siemplify.result.add_json("query_result", output)

    output_json["query_result"] = output

    total = output["count"]

    output_message = (
        "Successfully ran query: {} - Total Results: {} - "
        "Returned Results: {},".format(query, total, limit)
    )

    if output_json:
        siemplify.result.add_result_json(
            {"results": convert_dict_to_json_result_dict(output_json)}
        )

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
