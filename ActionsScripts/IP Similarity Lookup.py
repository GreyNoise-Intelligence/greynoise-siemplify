from constants import USER_AGENT
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "IP Similarity Lookup"


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

    minimum_score = siemplify.extract_action_param(
        param_name="minimum_score", default_value="90", is_mandatory=False, print_value=True
    )
    try:
        minimum_score = int(minimum_score)
    except:
        siemplify.LOGGER.info("Minimum Score does not appear to be a valid value")
        output_message = "Minimum Score does not appear to be a valid value"
        result_value = False
        status = EXECUTION_STATE_FAILED

    limit = siemplify.extract_action_param(
        param_name="limit", default_value="50", is_mandatory=False, print_value=True
    )
    try:
        limit = int(limit)
    except:
        siemplify.LOGGER.info("Limit does not appear to be a valid value")
        output_message = "Limit does not appear to be a valid value"
        result_value = False
        status = EXECUTION_STATE_FAILED

    output_message = "Successfully processed:"
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}
    invalid_ips = []
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))

        try:
            res = session.similar(ipaddr, min_score=minimum_score, limit=limit)

            if "similar_ips" in res:
                siemplify.result.add_json(str(ipaddr), res)
                output = res
                output_json[str(ipaddr)] = output
                siemplify.add_entity_insight(
                    ipaddr, to_insight(output), triggered_by=INTEGRATION_NAME
                )

                output_message = output_message + " {},".format(ipaddr)
            else:
                output = res
                output["message"] = "Address has no similarity results."
                siemplify.result.add_json(str(ipaddr), output)

            output_json[str(ipaddr)] = output

        except ValueError as e:
            siemplify.LOGGER.info(e)
            siemplify.LOGGER.info("Invalid Routable IP: {}".format(ipaddr))
            invalid_ips.append(ipaddr)
            continue

        except RequestFailure as e:
            siemplify.LOGGER.info("Unable to auth, please check API Key")
            output_message = "Unable to auth, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            break

        except RateLimitError as e:
            siemplify.LOGGER.info("Daily rate limit reached, please check API Key")
            output_message = "Daily rate limit reached, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            break

        except Exception as e:
            siemplify.LOGGER.info(e)
            siemplify.LOGGER.info("Unknown Error Occurred")
            output_message = "Unknown Error Occurred"
            result_value = False
            status = EXECUTION_STATE_FAILED
            break

    if output_json:
        siemplify.result.add_result_json({"results": convert_dict_to_json_result_dict(output_json)})

    if invalid_ips and result_value:
        invalid_ips_string = ""
        for item in invalid_ips:
            if invalid_ips_string == "":
                invalid_ips_string = str(item)
            else:
                invalid_ips_string = invalid_ips_string + ", " + str(item)
        output_message = output_message + " Invalid IPs skipped: {}".format(invalid_ips_string)

    siemplify.end(output_message, result_value, status)


def to_insight(self):
    content = ""
    content += "<table style='100%'><tbody>"
    content += (
        "<tr><td style='text-align: left;'><strong style='font-size: 17px'>"
        "Total Number of Similar IPs: <span>{total}</span></strong></td>".format(
            total=self["total"]
        )
    )
    content += "</tbody></table><br>"
    content += "<table style='100%'; border='1'; cellpadding='5'; cellspacing='5'><tbody>"
    content += "<tr><th style='text-align:left'>IP</th><th style='text-align:left'>Score</th><th style='text-align:left'>Feature Match</th></tr>"
    for item in self["similar_ips"][:10]:
        content += "<tr><td width='40%'>{ip}</td><td width='15%'>{score}</td><td>{feature}</td></tr>".format(
            ip=item["ip"], score=round(item["score"] * 100), feature=", ".join(item["features"])
        )
    content += "</tbody></table><br>"
    content += "<p>Only first 10 matches are displayed</p><br><br>"
    content += (
        '<p><strong>More Info: <a target="_blank" href=https://viz.greynoise.io/ip-similarity/'
        "{ip}>https://viz.greynoise.io/ip-similarity/{ip}</a></strong>&nbsp; </p>".format(
            ip=self["ip"]["ip"]
        )
    )

    return content


if __name__ == "__main__":
    main()
