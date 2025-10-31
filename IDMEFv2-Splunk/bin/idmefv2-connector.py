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

# ---------- Helpers ----------

def is_ip(s: str) -> bool:
    if not s:
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def extract_ip_from_url(url_or_ip):
    """
    Accepts either a plain IP (e.g. '10.0.0.1') or a URL (e.g. 'https://10.0.0.1:8000').
    Returns the hostname/IP if present, otherwise '0.0.0.0'.
    """
    if not url_or_ip:
        return "0.0.0.0"
    s = str(url_or_ip).strip()
    if is_ip(s):
        return s
    try:
        parsed_url = urlparse(s if "://" in s else f"//{s}", allow_fragments=False)
        host = parsed_url.hostname
        return host if host else "0.0.0.0"
    except Exception:
        return "0.0.0.0"

def get_current_datetime():
    """
    ISO-8601 with local timezone offset, second precision (e.g. '2025-09-01T12:20:00+02:00').
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")

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
    Determines the IDMEF classification based on the event's message.
    If alert_data is a dictionary, it utilizes the _raw field; if it is a string instead, it uses it directly.
    Returns the category in string format, e.g., "Attempt.Login" for failed logins.
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
    Extracts the service name from _raw.
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

def normalize_datetime(date_str):
    """
    Convert a 'YYYY-MM-DD HH:MM:SS' string into ISO-8601 with local timezone offset.
    Example: '2025-05-19 12:15:42' -> '2025-05-19T12:15:42+02:00'
    """
    if not date_str:
        logger.warning("Empty or null date string provided.")
        return None

    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        # assume the naive datetime is in local time
        tz = datetime.now().astimezone().tzinfo
        dt = dt.replace(tzinfo=tz)
        return dt.isoformat(timespec="seconds")
    except ValueError:
        logger.warning("Unrecognized datetime format: '%s'. Expected 'YYYY-MM-DD HH:MM:SS'.", date_str)
    except Exception as e:
        logger.warning("Failed to normalize datetime '%s': %s", date_str, e)

    return None

def to_int_list(x):
    """
    Try to parse a single value as an int and return [int].
    If not possible (e.g., '-', '', None), return [] so we can drop it in prune.
    """
    try:
        s = str(x).strip()
        v = int(s)
        return [v]
    except Exception:
        return []

def prune(obj):
    """
    Remove None, empty strings, empty lists and empty dicts recursively.
    """
    if isinstance(obj, dict):
        pruned = {}
        for k, v in obj.items():
            pv = prune(v)
            if pv is None:
                continue
            if pv == "":
                continue
            if pv == []:
                continue
            if pv == {}:
                continue
            pruned[k] = pv
        return pruned
    if isinstance(obj, list):
        pruned_list = []
        for item in obj:
            pi = prune(item)
            if pi is None or pi == "" or pi == [] or pi == {}:
                continue
            pruned_list.append(pi)
        return pruned_list
    return obj

# ---------- Template ----------
# The JSONPath are relative to the unified object passed to the converter.
template = {
    "Version": "2.D.V05",
    "ID": "$.id",
    "OrganisationName": "ElmiSoftware",
    "OrganisationId": "de0fdb525074492eabbf51d1842e43b8",
    "Description": "$.description",
    "Priority": (lambda priority: str(priority).capitalize() if priority else "Medium", "$.priority"),
    "CreateTime": lambda: get_current_datetime(),
    "StartTime": "$.StartTime",
    "Category": (lambda data: [classify_event(data)] if data else ["Attempt.Login"], "$._raw"),
    "Analyzer": {
        "Name": ( lambda t: t if t else "SPLUNK", "$.dvc_name" ),
        "Hostname": ( lambda t: t if t else "splunk.host", "$.dvc_host" ),
        "Type": ["$.type"],
        "Model": "$.vendor_product",
        "Category": ["SIEM"],
        "IP": (lambda x: extract_ip_from_url(x) if x else "0.0.0.0", "$.dvc_ip")
    },
    "Source": [{
        "IP": "$.src_ip",
        "Hostname": "$.src_host",
        "User": "$.src_user",
        "Email": "$.src_user",
        "Protocol": "$.protocol",
        "Port": (lambda p: (lambda L: L if L else None)(to_int_list(p)), "$.src_port"),
        "UnLocation": "$.src_country"
    }],
    "Target": [{
        "IP": "$.dest_ip",
        "Hostname": "$.dest_host",
        "Service": (
            lambda *args: next((v for v in args if v), "unknown_service"),
            "$.service", "$.process", "$.process_name"
        ),
        "User": "$.dest_user",
        "Email": "$.dest_user",
        "Port": (lambda p: (lambda L: L if L else None)(to_int_list(p)), "$.dest_port"),
        "UnLocation": "$.dest_country"
    }]
}

# ---------- Main ----------

def main():
    """
    Main functionalities:
    - Reading the payload from stdin.
    - Unifying the higher level data (payload) with the "result" field's content.
    - Verifying the presence of the mandatory fields and setting them as default values if they aren't present.
    - Calculating the dynamic classification and pre-calculating the target service.
    - Normalizing date fields.
    - Converting the message into the IDMEFv2 format using JSONConverter.
    - Sending the message to the specified IDMEFv2 endpoint.
    """
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--execute":
            payload = json.loads(sys.stdin.read())
            logger.info("Received payload: %s", json.dumps(payload, indent=4))

            config = payload.get("configuration", {})
            idmefv2_endpoint = config.get("idmefv2_endpoint", "http://default-endpoint")
            logger.info("Using generic Splunk template with dynamic classification.")

            result_data = payload.get("result", {})
            logger.info("Received result: %s", json.dumps(result_data, indent=4))

            # Ensure mandatory fields / defaults
            generated_id = str(uuid.uuid4())
            result_data["id"] = generated_id

            # Dynamic helpers
            result_data["_raw"] = result_data.get("_raw", "")
            result_data["idmef_category"] = classify_event(result_data)

            try:
                result_data["target_service"] = extract_service(result_data)
            except Exception as e:
                logger.warning("Unable to extract target service: %s. Defaulting to 'Unknown'.", e)
                result_data["target_service"] = "Unknown"

            # Merge configuration and other top-level payload fields
            result_data["configuration"] = config
            for key, value in payload.items():
                if key != "result":
                    result_data[key] = value

            # Normalize datetime fields
            normalized_start = None
            if "start_time" in result_data and result_data["start_time"]:
                normalized_start = normalize_datetime(result_data["start_time"])
            result_data["StartTime"] = normalized_start

            logger.info("Final result_data before conversion: %s", json.dumps(result_data, indent=4))

            # Convert to IDMEFv2
            try:
                converter = JSONConverter(template)
                converted, idmef_message = converter.convert(result_data)
            except Exception as conv_err:
                logger.error("Conversion error: %s", conv_err, exc_info=True)
                raise

            if not converted:
                raise Exception("IDMEF conversion failed.")

            # Remove null/empty fields
            idmef_message = prune(idmef_message)

            logger.info("Generated IDMEF message: %s", json.dumps(idmef_message, indent=4))

            # Send
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
