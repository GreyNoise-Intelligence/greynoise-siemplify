import requests
from constants import CODE_MESSAGES, USER_AGENT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Quick IP Lookup"


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

    ips = [
        entity
        for entity in siemplify.target_entities
        if entity.entity_type == EntityTypes.ADDRESS
    ]

    output_message = "Successfully processed: "
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))
        url = "https://api.greynoise.io/v2/noise/quick/"
        url = f"{url}{ipaddr}"

        res = requests.get(url, headers=headers)

        if res.status_code == 401:
            output_message = "Unable to auth, please check API Key.  This action requires a Paid Subscription."
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

        output = res.json()
        try:
            output["message"] = CODE_MESSAGES[output["code"]]
        except KeyError:
            output["message"] = "Code Message Unknown: {}".format(output["code"])

        siemplify.result.add_json(str(ipaddr), output)

        output_json[str(ipaddr)] = output

        output_message = output_message + "{},".format(ipaddr)

    if output_json:
        siemplify.result.add_result_json(
            {"results": convert_dict_to_json_result_dict(output_json)}
        )

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
