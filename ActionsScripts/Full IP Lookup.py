from constants import USER_AGENT
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Full IP Lookup"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    api_key = siemplify.extract_configuration_param(provider_name=INTEGRATION_NAME, param_name="GN API Key")

    session = GreyNoise(api_key=api_key, integration_name=USER_AGENT)

    ips = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.ADDRESS]

    output_message = "Successfully processed:"
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_json = {}
    invalid_ips = []
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))

        try:
            res = session.quick(str(ipaddr))
            if len(res) >= 1:
                if res[0]["noise"] and not res[0]["riot"]:
                    noise_res = session.ip(ipaddr)
                    siemplify.result.add_json(str(ipaddr), noise_res)
                    output = noise_res
                    output["noise"] = True
                    output_json[str(ipaddr)] = output
                    siemplify.add_entity_insight(ipaddr, to_noise_insight(output), triggered_by=INTEGRATION_NAME)

                    output_message = output_message + " {},".format(ipaddr)

                if res[0]["riot"] and not res[0]["noise"]:
                    riot_res = session.riot(ipaddr)
                    siemplify.result.add_json(str(ipaddr), riot_res)
                    output = riot_res
                    output_json[str(ipaddr)] = output
                    siemplify.add_entity_insight(ipaddr, to_riot_insight(output), triggered_by=INTEGRATION_NAME)

                    output_message = output_message + " {},".format(ipaddr)

                if res[0]["riot"] and res[0]["noise"]:
                    noise_res = session.ip(ipaddr)
                    riot_res = session.riot(ipaddr)
                    merged_res = noise_res.copy()
                    merged_res.update(riot_res)
                    siemplify.result.add_json(str(ipaddr), merged_res)
                    output = merged_res
                    output["noise"] = True
                    output_json[str(ipaddr)] = output
                    siemplify.add_entity_insight(ipaddr, to_noise_insight(noise_res), triggered_by=INTEGRATION_NAME)
                    siemplify.add_entity_insight(ipaddr, to_riot_insight(riot_res), triggered_by=INTEGRATION_NAME)

                    output_message = output_message + " {},".format(ipaddr)

                if not res[0]["noise"] and not res[0]["riot"]:
                    output = res[0]
                    output["seen"] = False
                    output[
                        "message"
                    ] = "Address has not been observed mass-scanning the internet by GreyNoise in the last 90 days."
                    siemplify.result.add_json(str(ipaddr), output)

            else:
                siemplify.LOGGER.info("Invalid Routable IP: {}".format(ipaddr))
                invalid_ips.append(ipaddr)

        except ValueError:
            siemplify.LOGGER.info("Invalid Routable IP: {}".format(ipaddr))
            invalid_ips.append(ipaddr)
            continue

        except RequestFailure:
            siemplify.LOGGER.info("Unable to auth, please check API Key")
            output_message = "Unable to auth, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            break

        except RateLimitError:
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


def to_noise_insight(self):
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
        "<td style='text-align: left; width: 30%;'>{last_seen}</td></tr>".format(last_seen=self["last_seen"])
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


def to_riot_insight(self):
    content = ""
    content += "<table style='100%'><tbody>"
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px;"
        "color:#7CFC00'><span>Benign Service</span></strong></td>"
    )
    content += "</tbody></table><br>"
    content += (
        "<p>This IP is from a known harmless services and/or organizations and can " "most likely be trusted.</p></br>"
    )
    content += "<table style='100%'><tbody>"
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Name: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{name}</td></tr>".format(name=self["name"])
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Category: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{category}</td></tr>".format(category=self["category"])
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Last Updated: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{last_updated}</td></tr>".format(
            last_updated=self["last_updated"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Explanation: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{explanation}</td></tr>".format(explanation=self["explanation"])
    )
    content += "</tbody></table><br><br>"
    content += (
        '<p><strong>More Info: <a target="_blank" href=https://viz.greynoise.io/riot/'
        "{ip}>https://viz.greynoise.io/riot/{ip}</a></strong>&nbsp; </p>".format(ip=self["ip"])
    )
    return content


if __name__ == "__main__":
    main()
