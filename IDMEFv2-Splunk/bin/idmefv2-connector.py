#!/usr/bin/env python3
"""
This script reads a JSON payload from stdin (typically sent by splunk),
maps it into an IDMEFv2 message using JSONconverter, and sends it to the configured endpoint.

The template is generic and dynamically adapted to the event's content,
assigning, for example, the correct classification.
"""

import sys
import os
import traceback
import uuid
import requests
import json
import logging
import logging.handlers
from datetime import datetime
from urllib.parse import urlparse

# Inserts the "lib" directory in the path to find JSONConverter.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "lib"))

def global_exception_hook(exc_type, exc_value, exc_traceback):
    try:
        log_path = os.path.join(
            os.environ.get("SPLUNK_HOME", "."),
            "var", "log", "splunk", "idmefv2_connector.log"
        )
        with open(log_path, "a") as f:
            f.write("Unhandled exception:\n")
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
    except Exception as log_err:
        sys.stderr.write("Error while writing the log: " + str(log_err) + "\n")
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)

sys.excepthook = global_exception_hook

try:
    from JSONConverter import JSONConverter  # Ensures JSONConverter.py is in the correct path
except Exception as e:
    global_exception_hook(*sys.exc_info())
    sys.exit(1)

def extract_ip_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.hostname if parsed_url.hostname else "unknown"

def get_current_datetime():
    current_datetime = datetime.utcnow()
    return current_datetime.strftime("%Y-%m-%dT%H:%M:%S.") + str(current_datetime.microsecond).zfill(6) + "Z"

def send_to_idmefv2_endpoint(message, idmefv2_endpoint):
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(idmefv2_endpoint, headers=headers, data=json.dumps(message))
        if response.status_code == 200:
            return 200
        else:
            raise Exception(f"API call returned status {response.status_code}: {response.text}")
    except requests.exceptions.RequestException as e:
        raise Exception(e)

def setup_logger(level=logging.INFO):
    logger_obj = logging.getLogger("idmefv2_connector")
    logger_obj.propagate = False
    logger_obj.setLevel(level)
    log_path = os.path.join(
        os.environ.get("SPLUNK_HOME", "."),
        "var", "log", "splunk", "idmefv2_connector.log"
    )
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=2500000000, backupCount=5
    )
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger_obj.addHandler(file_handler)
    return logger_obj

logger = setup_logger(logging.INFO)

def classify_event(alert_data):
    """
    Determins the IDMEF classification based on the event's message.
    If alert_data is a dictionary, it utilizes the _raw field; if it is a string instead, it uses it directly.
    Returns the category in string format, for example "Attempt.Login" for failed logins.
    """
    if isinstance(alert_data, dict):
        event_message = alert_data.get("_raw", "").lower()
    else:
        event_message = str(alert_data).lower()

    mapping = {
        "failed password": "Attempt.Login",
        "accepted password": "Information.LoginSuccess",
        "invalid user": "Information.UnauthorizedAccess",
        "sudo": "Intrusion.AdminCompromise",
        "brute force": "BruteForce-SSH",
        "scan": "Recon.Scanning",
        "malware": "Malicious.System",
        "ddos": "Availability.DDoS",
    }
    for key, value in mapping.items():
        if key in event_message:
            return value
    return "Other.Undetermined"

def extract_service(alert_data):
    """
    Estracts the name of the service form the the _raw field.
    If alert_data is a dictionary, it utilizes the _raw field; if it is a string instead, it uses it directly.
    Returns "SSH" when it finds "sshd", "HTTP" when it finds "httpd", "Unknown" otherwise.
    """
    if isinstance(alert_data, dict):
        event_message = alert_data.get("_raw", "").lower()
    else:
        event_message = str(alert_data).lower()
        
    if "sshd" in event_message:
        return "SSH"
    elif "httpd" in event_message:
        return "HTTP"
    return "Unknown"

# Updated template: the JSONPath are relative to the unified object we pass to the converter.
template = {
    "Version": "2.D.V04",
    "ID": "$.sid",
    "OrganisationName": "ElmiSoftware",
    "OrganizationId": "de0fdb525074492eabbf51d1842e43b8",
    "Description": "$._raw",
    "Priority": "Medium", # Always medium at the moment
    "CreateTime": lambda: get_current_datetime(),
    "StartTime": lambda: get_current_datetime(),
    "Category": (lambda data: [classify_event(data)], "$._raw"),
    "Analyzer": {
        "Name": "Splunk",
        "Hostname": "$.server_uri",
        "Type": "Cyber",
        "Model": "Splunk Enterprise",
        "Category": ["SIEM"],
        "IP": (lambda url: extract_ip_from_url(url), "$.server_uri")
    },
    "Source": [{
        "IP": "$.ip",
        "User": "$.user",
        "Port": "$.port"
    }],
    "Target": [{
        "IP": (lambda url: extract_ip_from_url(url), "$.server_uri"),
        "Service": "$.target_service",
        "Port": "$.port"
    }]
}

def main():
    """
    Main functionalities:
    - Reading the payload from stdin.
    - Unifying the higher level data (payload) with the "result" field's content.
    - Verifying the precence of the mandatory fields and setting them as default values if they aren't present.
    - Calculating the dynamic classification and pre-calculating the target service.
    - Converting the message into the IDMEFv2 format using JSONConverter.
    - Sending the message to the specified IDMEFv2 endpoint.
    """
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--execute":
            payload = json.loads(sys.stdin.read())
            logger.info("Received payload: %s", json.dumps(payload, indent=4))
            
            config = payload.get("configuration", {})
            idmefv2_endpoint = config.get("idmefv2_endpoint", "http://default-endpoint")
            # severity = config.get("severity", "Low")
            
            logger.info("Using generic Splunk template with dynamic classification.")
            
            # Obtain the "result" dictionary
            result_data = payload.get("result", {})
            logger.info("Received result: %s", json.dumps(result_data, indent=4))
            
            # Set _raw when missing
            result_data["_raw"] = result_data.get("_raw", "")
            result_data["idmef_category"] = classify_event(result_data)
            # result_data["severity"] = severity

            # Pre-calculate the target service, logging a warning message when missing
            try:
                target_service = extract_service(result_data)
            except Exception as e:
                logger.warning("Unable to extract target service: %s. Defaulting to 'Unknown'.", e)
                target_service = "Unknown"
            result_data["target_service"] = target_service

            # Unify the higher level data in the result_data dictionary
            for key, value in payload.items():
                if key != "result":
                    result_data[key] = value
            
            # Verify the mandatory fields and set them with default values when missing
            required_fields = {
                "sid": "unknown",
                "server_uri": "unknown",
                "ip": "0.0.0.0",
                "user": "unknown",
                "host": "unknown",
                "port": 0 
            }
            for field, default in required_fields.items():
                if field not in result_data or not result_data[field]:
                    logger.warning("Missing field '%s', defaulting to '%s'", field, default)
                    result_data[field] = default

            # Add the configuration
            result_data["configuration"] = config
            
            # Try to convert and logs specific errors when a field is missing
            try:
                converter = JSONConverter(template)
                converted, idmef_message = converter.convert(result_data)
            except Exception as conv_err:
                logger.error("Conversion error: %s", conv_err, exc_info=True)
                raise
            
            if not converted:
                raise Exception("IDMEF conversion failed.")
            
            logger.info("Generated IDMEF message: %s", json.dumps(idmef_message, indent=4))
            
            result = send_to_idmefv2_endpoint(idmef_message, idmefv2_endpoint)
            if result == 200:
                logger.info("Alert has been sent to IDMEFv2 Server.")
            else:
                raise Exception("Alert not sent properly.")
    except Exception as e:
        logger.error("Error occurred: %s", str(e), exc_info=True)
        raise

if __name__ == "__main__":
    main()