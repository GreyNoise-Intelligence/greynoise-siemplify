from constants import USER_AGENT
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
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

    session = GreyNoise(api_key=api_key, integration_name=USER_AGENT)

    ips = [
        entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS
    ]

    output_message = "Successfully processed: "
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))
        try:
            res = session.quick(str(ipaddr))
            if len(res) <= 1:
                output = res
                siemplify.result.add_json(str(ipaddr), output)
                output_json[str(ipaddr)] = output
                output_message = output_message + "{},".format(ipaddr)
            else:
                siemplify.LOGGER.info("Invalid Routable IP: {}".format(ipaddr))
                output_message = (
                    "Invalid input provided, ensure a routable IPv4 address is provided."
                )
                result_value = False
                status = EXECUTION_STATE_FAILED
                siemplify.end(output_message, result_value, status)

        except ValueError as e:
            siemplify.LOGGER.info("Invalid Routable IP: {}".format(ipaddr))
            output_message = "Invalid input provided, ensure a routable IPv4 address is provided."
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

        except RequestFailure as e:
            output_message = "Unable to auth, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

        except RateLimitError as e:
            output_message = "Daily rate limit reached, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

    if output_json:
        siemplify.result.add_result_json({"results": convert_dict_to_json_result_dict(output_json)})

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
