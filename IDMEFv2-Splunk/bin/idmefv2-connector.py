#!/usr/bin/env python3
"""
This script reads a JSON payload from stdin (typically sent by splunk),
maps it into an IDMEFv2 2.D.V08 message using JSONConverter, and sends it
to the configured endpoint.

Category is resolved with a priority order: explicit category from the
alert/search, a configurable mapping, a raw-text keyword fallback, and
finally "Other.Undetermined".
"""

import sys
import os
import csv
import re
import traceback
import uuid
import requests
import urllib3
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

# ---------- Constants ----------

APP_FOLDER_NAME = "IDMEFv2-Splunk"

IDMEFV2_VERSION = "2.D.V08"

DEFAULT_ORGANISATION_NAME = "CHANGE-ME"
DEFAULT_ORGANISATION_ID = "CHANGE-ME"

VALID_TYPES = {"Cyber", "Physical", "Availability", "Combined"}

VALID_PRIORITY = {"Unknown", "Info", "Low", "Medium", "High"}

PRIORITY_NORMALIZATION = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "med": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "unknown": "Unknown",
}

# Tier 3 fallback only: keyword match on the raw event text.
# "sudo" is intentionally not mapped to Access.Escalation here, since raw-text
# matching cannot tell a real privilege escalation from routine sudo usage.
CATEGORY_KEYWORDS = {
    "failed password": "Access.Unauthorized",
    "invalid user": "Access.Unauthorized",
    "accepted password": "Access.Authorized",
    "brute force": "Access.Forced",
    "scan": "Recon.Network",
    "malware": "Malware.Other",
    "ddos": "Availability.DDoS",
}

CATEGORY_TO_CAUSE = {
    "Access.Unauthorized": "Malicious",
    "Access.Authorized": "Normal",
    "Access.Forced": "Malicious",
    "Access.Escalation": "Malicious",
    "Recon.Network": "Malicious",
    "Availability.DDoS": "Malicious",
    "Other.Undetermined": "Unknown",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# IDMEFv2 2.D.V08 categoryEnum, used to validate explicit/configured categories.
VALID_CATEGORIES = frozenset({
    "Abuse.Coercion", "Abuse.Extermism", "Abuse.Grooming", "Abuse.Harassment",
    "Abuse.Trafficking", "Abuse.Other",
    "Access.Authorized", "Access.Backdoor", "Access.Clonned", "Access.Compromise",
    "Access.Escalation", "Access.Forced", "Access.Lost", "Access.Tailgating",
    "Access.Unauthorized", "Access.Other",
    "Availability.DDoS", "Availability.DoS", "Availability.Failure",
    "Availability.HeartBeat", "Availability.Misconfiguration", "Availability.Outage",
    "Availability.Overload", "Availability.Other",
    "Biological.Animal", "Biological.Epidemic", "Biological.Insect",
    "Biological.Zombies", "Biological.Other",
    "Climat.Drought", "Climat.LakeOutburst", "Climat.Wildfire", "Climat.Other",
    "Extraterrestrial.Aliens", "Extraterrestrial.Impact",
    "Extraterrestrial.SpaceWeather", "Extraterrestrial.Other",
    "Fraud.Copyright", "Fraud.Corruption", "Fraud.Espionnage", "Fraud.Masquerade",
    "Fraud.Phishing", "Fraud.Usage", "Fraud.Other",
    "Geophysical.Earthquake", "Geophysical.MassMovement", "Geophysical.Other",
    "Geophysical.Volcanic",
    "Hydro.Flood", "Hydro.Landslide", "Hydro.Wave", "Hydro.Other",
    "Insider.Malicious", "Insider.Negligent", "Insider.Other",
    "Malware.Adware", "Malware.Backdoor", "Malware.Cryptominer", "Malware.Downloader",
    "Malware.Ransomware", "Malware.Rootkit", "Malware.Spyware", "Malware.Trojan",
    "Malware.Virus", "Malware.Worm", "Malware.Other",
    "Meteo.Cold", "Meteo.Fog", "Meteo.Heat", "Meteo.Rain", "Meteo.Snow", "Meteo.Wind",
    "Meteo.Other",
    "National.Conflict", "National.Crime", "National.Cyber", "National.Economical",
    "National.Environemental", "National.Societal", "National.Terrorism", "National.Other",
    "Operational.Misuse", "Operational.Policy Violation", "Operational.Process Failure",
    "Operational.Other",
    "Recon.Aerial", "Recon.Landscape", "Recon.Network", "Recon.OSINT", "Recon.Other",
    "Sabotage.Data", "Sabotage.Destruction", "Sabotage.Disruption", "Sabotage.Equipment",
    "Sabotage.Graffiti", "Sabotage.Tampering", "Sabotage.Vandalism", "Sabotage.Other",
    "Safety.Accident", "Safety.Agression", "Safety.Explosion", "Safety.Fire",
    "Safety.Hostage", "Safety.Sexual", "Safety.Other",
    "SocialEng.Baiting", "SocialEng.Phishing", "SocialEng.Pretexting",
    "SocialEng.QuidProQuo", "SocialEng.Smishing", "SocialEng.Spear Phishing",
    "SocialEng.Vishing", "SocialEng.Other",
    "SupplyChain.Compromise", "SupplyChain.Disruption", "SupplyChain.Other",
    "Theft.Breaches", "Theft.Data", "Theft.Equiment", "Theft.FinInfo", "Theft.IP",
    "Theft.Machinery", "Theft.PII", "Theft.Other",
    "Other.Uncategorised", "Other.Undetermined", "Other.Test", "Other.ext-value",
})

# ---------- Helpers ----------

def is_ip(value: str) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def extract_ip_from_url(url_or_ip):
    """
    Accepts either a plain IP (e.g. '10.0.0.1') or a URL (e.g. 'https://10.0.0.1:8000').
    Returns the hostname/IP if present, otherwise None.
    """
    if not url_or_ip:
        return None
    candidate = str(url_or_ip).strip()
    if is_ip(candidate):
        return candidate
    try:
        parsed_url = urlparse(candidate if "://" in candidate else f"//{candidate}", allow_fragments=False)
        hostname = parsed_url.hostname
        return hostname if hostname else None
    except Exception:
        return None

def get_current_datetime():
    """
    ISO-8601 with local timezone offset, second precision (e.g. '2025-09-01T12:20:00+02:00').
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")

def send_to_idmefv2_endpoint(
    message,
    idmefv2_endpoint,
    auth_type="none",
    auth_token="",
    auth_username="",
    auth_password="",
    verify_ssl=True,
):
    """
    Sends the message with the configured authentication: none, a Bearer
    token, or Basic username/password. Mirrors the ES connector's auth model.
    """
    headers = {"Content-Type": "application/json", "Accept": "*/*"}
    request_auth = None

    normalized_auth_type = str(auth_type or "none").strip().lower()
    if normalized_auth_type == "bearer" and auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif normalized_auth_type == "basic" and auth_username:
        request_auth = (auth_username, auth_password)

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(
            idmefv2_endpoint,
            headers=headers,
            data=json.dumps(message),
            auth=request_auth,
            verify=verify_ssl,
        )
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

def is_email(value) -> bool:
    return bool(EMAIL_RE.match(str(value or "").strip()))

def parse_bool(value, default: bool) -> bool:
    """Parse Splunk's string-encoded booleans ('1'/'0', 'true'/'false', ...)."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "no", "n", "off"):
        return False
    return default

def normalize_type(value) -> list:
    """Map the raw event type to a valid IDMEFv2 Type, defaulting to Cyber."""
    text = str(value or "").strip().capitalize()
    return [text] if text in VALID_TYPES else ["Cyber"]

def normalize_priority(value) -> str:
    """Map the raw priority/urgency value to a valid IDMEFv2 Priority."""
    raw = str(value or "").strip().lower()
    mapped = PRIORITY_NORMALIZATION.get(raw)
    return mapped if mapped in VALID_PRIORITY else "Unknown"

def classify_event(alert_data) -> str:
    """
    Tier 3 fallback: keyword match on the raw event text, used only when no
    explicit or configured category is available.
    """
    if isinstance(alert_data, dict):
        event_message = alert_data.get("_raw", "").lower()
    else:
        event_message = str(alert_data).lower()

    for keyword, category in CATEGORY_KEYWORDS.items():
        if keyword in event_message:
            return category
    return "Other.Undetermined"

def load_category_mapping() -> dict:
    """
    Tier 2: admin-editable CSV translating arbitrary/legacy category values
    (e.g. a correlation search name, or a pre-V08 category string) into
    valid IDMEFv2 V08 categories.
    """
    mapping = {}
    csv_path = os.path.join(
        os.environ.get("SPLUNK_HOME", "."),
        "etc", "apps", APP_FOLDER_NAME, "lookups", "idmefv2_category_mapping.csv"
    )

    try:
        with open(csv_path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                source_value = (row.get("source_value") or "").strip().lower()
                target_category = (row.get("idmefv2_category") or "").strip()
                if source_value and target_category in VALID_CATEGORIES:
                    mapping[source_value] = target_category
    except (OSError, csv.Error) as e:
        logger.warning("Could not load category mapping file: %s", e)

    return mapping

def resolve_category(result_data) -> list:
    """
    Resolve Category with priority: explicit value from the alert/search (if
    already a valid V08 category, or translatable via the configurable
    mapping), then the raw-text keyword fallback, then Other.Undetermined.
    """
    explicit_value = str(result_data.get("Category") or result_data.get("category") or "").strip()

    if explicit_value:
        if explicit_value in VALID_CATEGORIES:
            return [explicit_value]
        mapped_category = load_category_mapping().get(explicit_value.lower())
        if mapped_category:
            return [mapped_category]

    return [classify_event(result_data)]

def cause_from_category(categories) -> str:
    """
    Derive Cause from the resolved Category. Unrecognized categories default
    to Unknown rather than assuming malicious intent.
    """
    for category in categories:
        if category.startswith("Malware."):
            return "Malicious"
        if category in CATEGORY_TO_CAUSE:
            return CATEGORY_TO_CAUSE[category]
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
        parsed_datetime = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        local_timezone = datetime.now().astimezone().tzinfo
        parsed_datetime = parsed_datetime.replace(tzinfo=local_timezone)
        return parsed_datetime.isoformat(timespec="seconds")
    except ValueError:
        logger.warning("Unrecognized datetime format: '%s'. Expected 'YYYY-MM-DD HH:MM:SS'.", date_str)
    except Exception as e:
        logger.warning("Failed to normalize datetime '%s': %s", date_str, e)

    return None

def to_int_list(value):
    """
    Try to parse a single value as an int and return [int].
    If not possible (e.g., '-', '', None), return [] so we can drop it in prune.
    """
    try:
        return [int(str(value).strip())]
    except Exception:
        return []

def prune(value):
    """
    Remove None, empty strings, empty lists and empty dicts recursively.
    """
    if isinstance(value, dict):
        pruned = {}
        for key, item in value.items():
            pruned_item = prune(item)
            if pruned_item is None or pruned_item == "" or pruned_item == [] or pruned_item == {}:
                continue
            pruned[key] = pruned_item
        return pruned
    if isinstance(value, list):
        pruned_list = []
        for item in value:
            pruned_item = prune(item)
            if pruned_item is None or pruned_item == "" or pruned_item == [] or pruned_item == {}:
                continue
            pruned_list.append(pruned_item)
        return pruned_list
    return value

# ---------- Template ----------
# The JSONPath are relative to the unified object passed to the converter.
template = {
    "Version": IDMEFV2_VERSION,
    "ID": "$.id",
    "OrganisationName": "$.organisation_name",
    "OrganisationId": "$.organisation_id",
    "Description": "$.description",
    "Priority": (lambda value: normalize_priority(value), "$.priority"),
    "CreateTime": lambda: get_current_datetime(),
    "StartTime": "$.StartTime",
    "Type": (lambda value: normalize_type(value), "$.type"),
    "Category": "$.idmefv2_category",
    "Cause": "$.idmefv2_cause",
    "Analyzer": {
        "Name": ( lambda value: value if value else "SPLUNK", "$.dvc_name" ),
        "Hostname": ( lambda value: value if value else "splunk.host", "$.dvc_host" ),
        "Model": "$.vendor_product",
        "Category": ["SIEM.SIEM"],
        "IP": (lambda value: extract_ip_from_url(value), "$.dvc_ip")
    },
    "Source": [{
        "ID": lambda: str(uuid.uuid4()),
        "IP": "$.src_ip",
        "Hostname": "$.src_host",
        "User": "$.src_user",
        "Email": (lambda value: value if is_email(value) else None, "$.src_user"),
        "Protocol": (lambda value: [str(value)] if value else None, "$.protocol"),
        "Port": (lambda value: (lambda port_list: port_list if port_list else None)(to_int_list(value)), "$.src_port"),
        "UnLocation": (
            lambda *candidates: next((candidate for candidate in candidates if candidate), None),
            "$.src_country", "$.unlocation"
        )
    }],
    "Target": [{
        "ID": lambda: str(uuid.uuid4()),
        "IP": "$.dest_ip",
        "Hostname": "$.dest_host",
        "Service": (
            lambda *candidates: next((candidate for candidate in candidates if candidate), "unknown_service"),
            "$.service", "$.process", "$.process_name"
        ),
        "User": "$.dest_user",
        "Email": (lambda value: value if is_email(value) else None, "$.dest_user"),
        "Port": (lambda value: (lambda port_list: port_list if port_list else None)(to_int_list(value)), "$.dest_port"),
        "UnLocation": (
            lambda *candidates: next((candidate for candidate in candidates if candidate), None),
            "$.dest_country", "$.unlocation"
        )
    }]
}

# ---------- Main ----------

def main():
    """
    Main functionalities:
    - Reading the payload from stdin.
    - Unifying the higher level data (payload) with the "result" field's content.
    - Resolving OrganisationName/OrganisationId from the alert action configuration.
    - Resolving Category (explicit value, configurable mapping, raw-text fallback) and Cause.
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
            auth_type = str(config.get("auth_type") or "none").strip().lower()
            auth_token = str(config.get("auth_token") or "").strip()
            auth_username = str(config.get("auth_username") or "").strip()
            auth_password = str(config.get("auth_password") or "").strip()
            verify_ssl = parse_bool(config.get("verify_ssl"), True)
            logger.info("Using generic Splunk template with dynamic classification.")

            result_data = payload.get("result", {})
            logger.info("Received result: %s", json.dumps(result_data, indent=4))

            # Ensure mandatory fields / defaults
            generated_id = str(uuid.uuid4())
            result_data["id"] = generated_id

            result_data["organisation_name"] = config.get("organisation_name") or DEFAULT_ORGANISATION_NAME
            result_data["organisation_id"] = config.get("organisation_id") or DEFAULT_ORGANISATION_ID

            # Dynamic helpers
            result_data["_raw"] = result_data.get("_raw", "")

            categories = resolve_category(result_data)
            result_data["idmefv2_category"] = categories
            result_data["idmefv2_cause"] = cause_from_category(categories)

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
            result = send_to_idmefv2_endpoint(
                idmef_message,
                idmefv2_endpoint,
                auth_type=auth_type,
                auth_token=auth_token,
                auth_username=auth_username,
                auth_password=auth_password,
                verify_ssl=verify_ssl,
            )
            if result == 200:
                logger.info("Alert has been sent to IDMEFv2 Server.")
            else:
                raise Exception("Alert not sent properly.")
    except Exception as e:
        logger.error("Error occurred: %s", str(e), exc_info=True)
        raise

if __name__ == "__main__":
    main()
