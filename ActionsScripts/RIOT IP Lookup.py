import requests
from constants import USER_AGENT
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict, output_handler

INTEGRATION_NAME = "GreyNoise"

SCRIPT_NAME = "RIOT IP Lookup"


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
        url = "https://api.greynoise.io/v2/riot/"
        url = f"{url}{ipaddr}"

        res = requests.get(url, headers=headers)

        if res.status_code == 401:
            output_message = "Unable to auth, please check API Key.  This action requires a Paid Subscription."
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.end(output_message, result_value, status)

        siemplify.result.add_json(str(ipaddr), res.json())

        output_json[str(ipaddr)] = res.json()

        if res.status_code == 200 and res.json()["riot"]:
            siemplify.add_entity_insight(
                ipaddr, to_insight(res.json()), triggered_by=INTEGRATION_NAME
            )

        output_message = output_message + "{},".format(ipaddr)

    if output_json:
        siemplify.result.add_result_json(
            {"results": convert_dict_to_json_result_dict(output_json)}
        )

    siemplify.end(output_message, result_value, status)


def to_insight(self):
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
        "<tr><td style='text-align: left; width: 30%;'><strong>Category: </strong></td>"
        "<td style='text-align: left; width: 30%;'>{category}</td></tr>".format(
            category=self["category"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Last Updated: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{last_updated}</td></tr>".format(
            last_updated=self["last_updated"]
        )
    )
    content += (
        "<tr><td style='text-align: left; width: 30%;'><strong>Explanation: </strong>"
        "</td><td style='text-align: left; width: 30%;'>{explanation}</td></tr>".format(
            explanation=self["explanation"]
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
