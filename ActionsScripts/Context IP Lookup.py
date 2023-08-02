from constants import USER_AGENT
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Context IP Lookup"


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

    output_message = "Successfully processed:"
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}
    invalid_ips = []
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))

        try:
            res = session.ip(ipaddr)

            if res["seen"]:
                siemplify.result.add_json(str(ipaddr), res)
                output = res
                output["noise"] = True
                output_json[str(ipaddr)] = output
                siemplify.add_entity_insight(
                    ipaddr, to_insight(output), triggered_by=INTEGRATION_NAME
                )

                output_message = output_message + " {},".format(ipaddr)
            else:
                output = res
                output["noise"] = False
                output[
                    "message"
                ] = "Address has not been observed mass-scanning the internet by GreyNoise in the last 90 days."
                siemplify.result.add_json(str(ipaddr), output)

            output_json[str(ipaddr)] = output

        except ValueError as e:
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

        except Exception:
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
        "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>"
        "Noise: <span>{noise}</span></strong></td>".format(noise=self["seen"])
    )
    content += "</tbody></table><br>"
    content += (
        "<p>This IP has been observed opportunistically scanning the internet "
        "and is not directly targeting your organization.</p></br>"
    )
    content += "<table style='100%'><tbody>"
    if self["classification"] == "malicious":
        content += (
            "<tr><td style='text-align: left; width: 30%; color: red'><strong>"
            "Classification: </strong></td><td style='text-align: left; width: 30%; "
            "color: red'>{classification}</td>"
            "</tr>".format(classification=self["classification"])
        )
    elif self["classification"] == "benign":
        content += (
            "<tr><td style='text-align: left; width: 30%; color: #1dbf11'><strong>"
            "Classification: </strong></td><td style='text-align: left; width: 30%;"
            " color: #1dbf11'>{classification}</td>"
            "</tr>".format(classification=self["classification"])
        )
    else:
        content += (
            "<tr><td style='text-align: left; width: 30%;'><strong>Classification: "
            "</strong></td><td style='text-align: left; width: 30%;'>{classification}"
            "</td></tr>".format(classification=self["classification"])
        )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Last Seen: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{last_seen}</td></tr>".format(
            last_seen=self["last_seen"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Organization: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{organization}</td></tr>".format(
            organization=self["metadata"]["organization"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Country: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{organization}</td></tr>".format(
            organization=self["metadata"]["country"]
        )
    )
    content += "</tbody></table><br><br>"
    content += (
        '<p><strong>More Info: <a target="_blank" href=https://viz.greynoise.io/ip/'
        "{ip}>https://viz.greynoise.io/ip/{ip}</a></strong>&nbsp; </p>".format(ip=self["ip"])
    )

    return content


if __name__ == "__main__":
    main()
