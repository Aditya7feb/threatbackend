from flask import jsonify
from appDB import malwareThreats, malwareTechnicals, associatedIndicators


def extractEntries(data):
    entries_json = [entry.__dict__ for entry in data]
    for entry in entries_json:
        for key, value in entry.items():
            if value is None:
                entry[key] = "Not Availaible"
        del entry["_sa_instance_state"]
    return entries_json


def get_malware_threats(malware_threat_id):
    try:
        # Fetch the malware threat by ID
        threat = malwareThreats.query.get(malware_threat_id)

        if threat is None:
            return jsonify({"error": "Malware threat not found"}), 404

        # Access related technicals and indicators through the threat object
        technicals = threat.technicals
        indicators = threat.indicators

        # Serialize the threat
        serialized_threat = {
            "id": threat.id,
            "malwareName": threat.malwareName,
            "recordDate": threat.recordDate,
            "category": threat.category,
            "description": threat.description,
            "ttp": threat.ttp,
            "associatedThreatActors": threat.associatedThreatActors,
            "attackVectors": threat.attackVectors,
            "associatedVulns": threat.associatedVulns,
            "remarks": threat.remarks,
        }

        # Serialize related technicals
        serialized_technicals = []
        if technicals:  # Check if there are technicals associated with the threat
            for technical in technicals:
                serialized_technical = {
                    "id": technical.id,
                    "technicalSummary": technical.technicalSummary,
                    "referenceLinks": technical.referenceLinks,
                    "imageHeading": technical.imageHeading,
                    "imageLink": technical.imageLink,
                }
                serialized_technicals.append(serialized_technical)

        # Serialize related indicators
        serialized_indicators = []
        if indicators:  # Check if there are indicators associated with the threat
            for indicator in indicators:
                serialized_indicator = {
                    "id": indicator.id,
                    "ip": indicator.ip,
                    "domains": indicator.domains,
                    "hashes": indicator.hashes,
                }
                serialized_indicators.append(serialized_indicator)

        # Return serialized data
        return (
            jsonify(
                {
                    "Threat": serialized_threat,
                    "Technicals": serialized_technicals,
                    "Indicators": serialized_indicators,
                }
            ),
            200,
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "An error occurred while processing the request",
                    "msg": str(e),
                }
            ),
            500,
        )
