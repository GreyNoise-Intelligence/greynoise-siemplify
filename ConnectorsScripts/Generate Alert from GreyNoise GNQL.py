from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, unix_now

import sys
import requests


CONNECTOR_NAME = "GreyNoise GNQL Connector"
VENDOR = "GreyNoise"
PRODUCT = "GreyNoise"


@output_handler
def main(is_test_run):
    alerts = []
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME

    if (is_test_run):
        siemplify.LOGGER.info("***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    siemplify.LOGGER.info("==================== Main - Param Init ====================")

    query = siemplify.extract_connector_param("query", print_value=True)
    limit = siemplify.extract_connector_param("limit", default_value="10", is_mandatory=False, print_value=True)
    api_key = siemplify.extract_connector_param("GN API Key", print_value=False)
    

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "key": api_key,
        "User-Agent": "siemplify-v1.0.0",
    }

    siemplify.LOGGER.info("------------------- Main - Started -------------------")

    try:
        url = ("https://api.greynoise.io/v2/experimental/gnql?query={}&size={}").format(query,limit)
    
        res = requests.get(url, headers=headers)
        
        if res.status_code == 200 and res.json()['count'] > 0:    
            output = res.json()
            
            for result in output['data']:
                datetime_in_unix_time = unix_now()
                alert_id = str(datetime_in_unix_time) + "-" + result['ip']

                # Creating the event by calling create_event() function
                created_event = create_event(siemplify, alert_id, result, datetime_in_unix_time)
                # Creating the alert by calling create_alert() function
                created_alert = create_alert(siemplify, alert_id, result, datetime_in_unix_time, created_event)

                # Checking that the created_alert is not None
                if created_alert is not None:
                    alerts.append(created_alert)
                    siemplify.LOGGER.info(f"Added Alert {alert_id} to package results")

    
    except Exception as e:
        siemplify.LOGGER.error("Failed to process alert {}".format(alert_id), alert_id=alert_id)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("------------------- Main - Finished -------------------")
    siemplify.return_package(alerts)
    
def create_alert(siemplify, alert_id, result, datetime_in_unix_time, created_event):
    """
    Returns an alert which is one event that contains one unread email message
    """
    siemplify.LOGGER.info(f"-------------- Started processing Alert {alert_id}")
    create_event = None
    alert_info = AlertInfo()

    # Initializes the alert_info Characteristics Fields
    alert_info.display_id = f"{alert_id}" # Each alert needs to have a unique id, otherwise it won't  create a case with the same alert id.
    alert_info.ticket_id = f"{alert_id}" # In default, ticket_id = display_id. However, if for some reason the external alert id is different from  the display_id, you can save the original external alert id in the "ticket_id" field.
    alert_info.name = str(result['ip']) + ' has been observed mass-scanning the internet'
    alert_info.start_time = datetime_in_unix_time # Time should be saved in UnixTime. You may use SiemplifyUtils.convert_datetime_to_unix_time, or SiemplifyUtils.convert_string_to_datetime
    alert_info.end_time = datetime_in_unix_time # Time should be saved in UnixTime. You may use SiemplifyUtils.convert_datetime_to_unix_time, or SiemplifyUtils.convert_string_to_datetime
    alert_info.SourceAddress = result['ip']
    alert_info.EventTime = result['last_seen']
    alert_info.rule_generator = f"GreyNoise Ingestion"
    alert_info.priority = 60  # Informative = -1,Low = 40,Medium = 60,High = 80,Critical = 100.
    alert_info.device_vendor = VENDOR # The field will be fetched from the Original Alert. If you build this alert manually, state the source vendor of the data. (ie: Microsoft, Mcafee)
    alert_info.device_product = PRODUCT # The field will be fetched from the Original Alert. If you build this alert manually, state the source product of the data. (ie: ActiveDirectory, AntiVirus)
    # ----------------------------- Alert Fields initialization END -----------------------------#
    siemplify.LOGGER.info(f"---------- Events creating started for alert  {alert_id}")
    try:
        if created_event is not None:
            alert_info.events.append(created_event)
        siemplify.LOGGER.info(f"Added Event {alert_id} to Alert {alert_id}")
    # Raise an exception if failed to process the event
    except Exception as e:
        siemplify.LOGGER.error(f"Failed to process event {alert_id}")
        siemplify.LOGGER.exception(e)

    return alert_info

def create_event(siemplify, alert_id, result, datetime_in_unix_time):
    """
    Returns the digested data of a single unread email
    """
    siemplify.LOGGER.info(f"--- Started processing Event:  alert_id: {alert_id} | event_id: {alert_id}")
    event = {}
    event["StartTime"] = datetime_in_unix_time # Time should be saved in UnixTime. You may use SiemplifyUtils.convert_datetime_to_unix_time, or SiemplifyUtils.convert_string_to_datetime
    event["EndTime"] = datetime_in_unix_time # Time should be saved in UnixTime. You may use SiemplifyUtils.convert_datetime_to_unix_time, or SiemplifyUtils.convert_string_to_datetime
    event["event_name"] = "Mass Scanning IP Detected" 
    event["device_product"] = PRODUCT # ie: "device_product" is the field name that describes the product the event originated from.

    event["SourceAddress"] = result["ip"]
    event["EventTime"] = result["last_seen"]
    event["Classification"] = result["classification"]


    siemplify.LOGGER.info(f"--- Finished processing Event: alert_id: {alert_id} | event_id: {alert_id}")
    return event



if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == 'True')
    main(is_test_run)