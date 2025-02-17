import json
from dataclasses import dataclass
import os
from typing import List, Optional
import requests
from dotenv import load_dotenv
import time  # Importa il modulo time per utilizzare sleep

load_dotenv()

API_URL = os.getenv("API_URL")
SPLUNK_GEN_API = os.getenv("SPLUNK_GEN_API")
VERSION = os.getenv("VERSION")

@dataclass
class AnalyserDTO:
    Name: str
    Hostname: str
    Type: str
    Model: str
    Category: List[str]
    IP: str

@dataclass
class IPInfoDTO:
    IP: str

@dataclass
class MappedAlertDTO:
    Version: Optional[str] = None
    ID: Optional[str] = None
    OrganisationName: Optional[str] = None
    OrganizationId: Optional[str] = None
    Description: Optional[str] = None
    Priority: Optional[str] = None
    CreateTime: Optional[str] = None
    StartTime: Optional[str] = None
    Category: Optional[List[str]] = None
    Analyzer: Optional[AnalyserDTO] = None
    Source: Optional[List[IPInfoDTO]] = None
    Target: Optional[List[IPInfoDTO]] = None

    def to_dict(self):
        """
        Converte la dataclass in un dizionario, utile per la serializzazione JSON.
        """
        result = self.__dict__.copy()  # Copia dei dati della dataclass
        
        # Converti l'oggetto Analyser in un dizionario
        if self.Analyzer:
            result['Analyzer'] = self.Analyzer.__dict__
        
        # Converti le liste Source e Target
        if self.Source:
            result['Source'] = [s.__dict__ for s in self.Source]
        if self.Target:
            result['Target'] = [t.__dict__ for t in self.Target]
        
        return result

def map_alert() -> MappedAlertDTO:
    """
    Ottieni i dati dall'API e mappa la risposta in un oggetto MappedAlertDTO.
    """
    response = requests.get(SPLUNK_GEN_API)
    if response.status_code == 200:
        dati = response.json() 

        IDMFV2 = MappedAlertDTO(
            Version = "2.D.V" + VERSION,
            ID = dati.get("cid", ""),
            OrganisationName = "ElmiSoftware",
            OrganizationId = dati.get("cid", ""),
            Description = dati.get("behaviors", {})[0].get("description", ""),
            Priority = dati.get("max_severity_displayname", ""),
            CreateTime = dati.get("created_timestamp", ""),
            StartTime = dati.get("first_behavior", ""),
            Category = ["Test.test"],
            Analyzer = AnalyserDTO(
                Name = dati.get("behaviors", {})[0].get("display_name", ""),
                Hostname = dati.get("device", {}).get("hostname", ""),
                Type = "Cyber",
                Model = dati.get("device", {}).get("os_version", ""),
                Category = ["SPAM"],
                IP = dati.get("device", {}).get("local_ip", ""),
            ),
            Source = [IPInfoDTO(
                IP= dati.get("device", {}).get("local_ip", ""),
            )],
            Target = [IPInfoDTO(
                IP= "195.103.203.230",
            )]
        )
        return IDMFV2
    else:
        print(f"Errore durante il recupero dei dati: {response.status_code}")
        return None

def send_to_CPSIEM(message):
    """
    Invia il messaggio serializzato in JSON all'API configurata.
    """
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(API_URL, headers=headers, data=json.dumps(message))
        response.raise_for_status()
        print(f"Messaggio inviato con successo: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Errore durante l'invio del messaggio: {e}")

def main():
    while True:  # Ciclo infinito per eseguire il codice continuamente
        try:
            alert = map_alert()

            if alert is not None:
                alert_dict = alert.to_dict()
                json_str = json.dumps(alert_dict, indent=4)
                print(json_str)
                send_to_CPSIEM(alert_dict)

            time.sleep(10)  # Pausa di 20 secondi prima della prossima esecuzione

        except KeyboardInterrupt:
            print("Interruzione da tastiera ricevuta. Uscita dal programma.")
            break  # Esce dal ciclo se viene premuto Ctrl+C

if __name__ == "__main__":
    main()
