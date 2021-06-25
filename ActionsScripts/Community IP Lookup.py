import requests
from constants import USER_AGENT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "Community IP Lookup"


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
        "User-Agent": "community-" + USER_AGENT,
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
    community_url = "https://api.greynoise.io/v3/community/"
    for ipaddr in ips:
        siemplify.LOGGER.info("Started processing IP: {}".format(ipaddr))
        url = f"{community_url}{ipaddr}"

        res = requests.get(url, headers=headers)

        if res.status_code == 200 and res.json()["noise"]:

            siemplify.result.add_json(str(ipaddr), res.json())

            output = res.json()

            output_json[str(ipaddr)] = output

            siemplify.add_entity_insight(
                ipaddr, to_noise_insight(output), triggered_by=INTEGRATION_NAME
            )

            output_message = output_message + "{},".format(ipaddr)

        elif res.status_code == 200 and res.json()["riot"]:

            siemplify.result.add_json(str(ipaddr), res.json())

            output = res.json()

            output_json[str(ipaddr)] = output

            siemplify.add_entity_insight(
                ipaddr, to_riot_insight(output), triggered_by=INTEGRATION_NAME
            )

            output_message = output_message + "{},".format(ipaddr)

        elif res.status_code == 401:
            output_message = "Unable to auth, please check API Key"
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

        else:
            output = res.json()
            siemplify.result.add_json(str(ipaddr), output)

            output_json[str(ipaddr)] = output

    if output_json:
        siemplify.result.add_result_json(
            {"results": convert_dict_to_json_result_dict(output_json)}
        )

    siemplify.end(output_message, result_value, status)


def to_noise_insight(self):
    content = ""
    content += "<table style='100%'><tbody>"
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong style='font-size: 17px'>"
        "Noise: <span>{noise}</span></strong></td>".format(noise=self["noise"])
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
            "<tr><td style='text-align: left; width: 30%; color: #7CFC00'><strong>"
            "Classification: </strong></td><td style='text-align: left; width: 30%;"
            " color: #7CFC00'>{classification}</td>"
            "</tr>".format(classification=self["classification"])
        )
    else:
        content += (
            "<tr><td style='text-align: left; width: 30%;'><strong>Classification: "
            "</strong></td><td style='text-align: left; width: 30%;'>{classification}"
            "</td></tr>".format(classification=self["classification"])
        )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Name: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{name}</td></tr>".format(
            name=self["name"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Last Seen: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{last_seen}</td></tr>".format(
            last_seen=self["last_seen"]
        )
    )
    content += "</tbody></table><br><br>"
    content += (
        '<p><strong>More Info: <a target="_blank" href=https://viz.greynoise.io/ip/'
        "{ip}>https://viz.greynoise.io/ip/{ip}</a></strong>&nbsp; </p>".format(
            ip=self["ip"]
        )
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
        "<p>This IP is from a known harmless services and/or organizations and can "
        "most likely be trusted.</p></br>"
    )
    content += "<table style='100%'><tbody>"
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Name: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{name}</td></tr>".format(
            name=self["name"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Last Updated: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{last_updated}</td></tr>".format(
            last_updated=self["last_seen"]
        )
    )
    content += "</tbody></table><br><br>"
    content += (
        '<p><strong>More Info: <a target="_blank" href=https://viz.greynoise.io/riot/'
        "{ip}>https://viz.greynoise.io/riot/{ip}</a></strong>&nbsp; </p>".format(
            ip=self["ip"]
        )
    )

    return content


if __name__ == "__main__":
    main()
