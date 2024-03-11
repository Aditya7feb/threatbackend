from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from appDB import (
    db,
    malwareThreats,
    malwareTechnicals,
    associatedIndicators,
    zeroDayVuln,
)
from functions import extractEntries


# Creating Flask App
app = Flask(__name__)
CORS(app)
# Database Name
db_name = "malware_report.db"
# Configuring SQLite Database URI
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_name
# Suppresses warning while tracking modifications
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# Initialising SQLAlchemy with Flask App
migrate = Migrate(render_as_batch=True)
db.init_app(app)
migrate.init_app(app, db)


""" app.py file """


@app.route("/api/v1/newMalwareEntry", methods=["POST"])
def NewMalwareEntryAPI():
    if request.method == "POST":
        try:
            data = request.get_json()
            new_threat = malwareThreats(**data)
            validation_result = new_threat.validate_fields()
            if validation_result:
                return validation_result
            else:
                # Save the new threat to the database
                db.session.add(new_threat)
                db.session.commit()
                return (
                    jsonify({"success": "New malware threat entry added successfully"}),
                    201,
                )
        except Exception as e:
            return (
                jsonify(
                    {
                        "error": "An error occurred while processing the request",
                        "msg": e.__str__(),
                    }
                ),
                500,
            )


@app.route("/api/v1/newAssociatedIndicatorEntry", methods=["POST"])
def NewAssociatedIndicatorEntryAPI():
    if request.method == "POST":
        try:
            data = request.get_json()
            new_indicator = associatedIndicators(**data)
            validation_result = new_indicator.validate_fields()
            if validation_result:
                return validation_result
            else:
                db.session.add(new_indicator)
                db.session.commit()

                return (
                    jsonify(
                        {"success": "New associated indicator entry added successfully"}
                    ),
                    201,
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


@app.route("/api/v1/newMalwareTechnicalsEntry", methods=["POST"])
def NewMalwareTechnicalsEntryAPI():
    if request.method == "POST":
        try:
            data = request.get_json()
            new_malwareTechnicals = malwareTechnicals(**data)
            validation_result = new_malwareTechnicals.validate_fields()
            if validation_result:
                return validation_result
            else:
                # Save the new threat to the database
                db.session.add(new_malwareTechnicals)
                db.session.commit()
                return (
                    jsonify(
                        {"success": "New malware technicals entry added successfully"}
                    ),
                    201,
                )
        except Exception as e:
            return (
                jsonify(
                    {
                        "error": "An error occurred while processing the request",
                        "msg": e.__str__(),
                    }
                ),
                500,
            )


@app.route("/api/v1/malwareThreats", methods=["GET"])
def get_malware_threats():
    try:
        threats = malwareThreats.query.all()
        serialized_threats = extractEntries(threats)
        return jsonify(serialized_threats), 200
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "An error occurred while processing the request",
                    "msg": e.__str__(),
                }
            ),
            500,
        )


@app.route("/api/v1/associatedIndicators/<int:malware_threat_id>", methods=["GET"])
def get_associated_indicators(malware_threat_id):
    try:
        threats = associatedIndicators.query.filter_by(
            malware_threat_id=malware_threat_id
        ).all()
        serialized_threats = extractEntries(threats)
        return jsonify(serialized_threats), 200
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "An error occurred while processing the request",
                    "msg": e.__str__(),
                }
            ),
            500,
        )


@app.route("/api/v1/malwareTechnicals/<int:malware_threat_id>", methods=["GET"])
def get_malware_technicals_indicators(malware_threat_id):
    try:
        threats = malwareTechnicals.query.filter_by(
            malware_threat_id=malware_threat_id
        ).all()
        serialized_threats = extractEntries(threats)
        return jsonify(serialized_threats), 200
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "An error occurred while processing the request",
                    "msg": e.__str__(),
                }
            ),
            500,
        )


@app.route("/api/v1/getMalwareDetails/<int:malware_threat_id>", methods=["GET"])
def get_malware_details(malware_threat_id):
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
        # serialized_technicals = []
        if technicals:  # Check if there are technicals associated with the threat
            # for technical in technicals:
            technical = technicals
            serialized_technical = {
                "technicalSummary": technical.technicalSummary,
                "referenceLinks": technical.referenceLinks,
                "imageHeading": technical.imageHeading,
                "imageLink": technical.imageLink,
            }
            # serialized_technicals.append(serialized_technical)

        # Serialize related indicators
        serialized_indicators = []
        if indicators:  # Check if there are indicators associated with the threat
            for indicator in indicators:
                serialized_indicator = {
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
                    # "Technicals": serialized_technicals,
                    "Technical": serialized_technical,
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


@app.route("/api/v1/createMalwareThreat", methods=["POST"])
def create_malware_threat():
    try:
        # Extract data from the request JSON
        data = request.json
        threat_data = data.get("threat")
        # technical_data = data.get("technical", [])
        technical_data = data.get("technical")
        indicator_data = data.get("indicator", [])

        # Create a new malware threat entry
        print(threat_data)
        threat = malwareThreats(**threat_data)
        db.session.add(threat)
        db.session.commit()

        # Create new technical entries associated with the threat
        # for tech_data in technical_data:
        tech_data = technical_data
        tech_data["malware_threat_id"] = threat.id
        technical = malwareTechnicals(**tech_data)
        db.session.add(technical)

        # Create new indicator entries associated with the threat
        for ind_data in indicator_data:
            ind_data["malware_threat_id"] = threat.id
            indicator = associatedIndicators(**ind_data)
            db.session.add(indicator)

        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Malware threat created successfully",
                    "malware_threat_id": threat.id,
                }
            ),
            201,
        )
    except IntegrityError as e:
        db.session.rollback()
        if "UNIQUE constraint failed: malware_threats.malwareName" in str(e):
            existing_threat = malwareThreats.query.filter_by(
                malwareName=threat_data["malwareName"]
            ).first()
            existing_threat_id = existing_threat.id if existing_threat else None
            return (
                jsonify(
                    {
                        "error": "Malware threat with the given name already exists",
                        "malware_threat_id": existing_threat_id,
                    }
                ),
                400,
            )
        else:
            return (
                jsonify(
                    {
                        "error": "An error occurred while creating the malware threat",
                        "msg": str(e),
                    }
                ),
                500,
            )
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "An error occurred while creating the malware threat",
                    "msg": str(e),
                }
            ),
            500,
        )


@app.route("/api/v1/getAllMalwareThreats", methods=["GET"])
def get_all_malware_threats():
    try:
        # Fetch all malware threats
        threats = malwareThreats.query.all()

        # Initialize list to store serialized threats
        serialized_threats = []

        # Iterate over each threat and serialize it
        for threat in threats:
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
            # serialized_technicals = []
            # serialized_technicals = {}
            technical = threat.technicals
            # for technical in threat.technicals:
            serialized_technical = {
                "autoID": technical.autoID,
                "technicalSummary": technical.technicalSummary,
                "referenceLinks": technical.referenceLinks,
                "imageHeading": technical.imageHeading,
                "imageLink": technical.imageLink,
            }
            # serialized_technicals.append(serialized_technical)
            serialized_threat["Malware_Technicals"] = serialized_technical

            # Serialize related indicators
            serialized_indicators = []
            for indicator in threat.indicators:
                serialized_indicator = {
                    "autoID": indicator.autoID,
                    "ip": indicator.ip,
                    "domains": indicator.domains,
                    "hashes": indicator.hashes,
                }
                serialized_indicators.append(serialized_indicator)
            serialized_threat["Associated_Indicators"] = serialized_indicators

            serialized_threats.append(serialized_threat)

        # Return serialized data
        return jsonify(serialized_threats), 200
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


@app.route("/api/v1/deleteMalwareThreat", methods=["DELETE"])
def delete_malware_threat():
    try:
        # Extract threat ID from the request JSON
        data = request.json
        threat_id = data.get("id")

        # Check if the threat ID is provided
        if threat_id is None:
            return jsonify({"error": "Threat ID is required in the request body"}), 400

        # Fetch the threat by ID
        threat = malwareThreats.query.get(threat_id)

        # Check if the threat exists
        if threat is None:
            return jsonify({"error": "Malware threat not found"}), 404

        # Delete related technicals
        technicals = threat.technicals
        # for technical in technicals:
        technical = technicals
        db.session.delete(technical)

        # Delete related indicators
        indicators = threat.indicators
        for indicator in indicators:
            db.session.delete(indicator)

        # Delete the threat
        db.session.delete(threat)
        db.session.commit()

        return (
            jsonify(
                {"message": "Malware threat and related data deleted successfully"}
            ),
            200,
        )
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "An error occurred while deleting the malware threat",
                    "msg": str(e),
                }
            ),
            500,
        )


@app.route("/api/v1/deleteAssociatedIndicator/<int:indicator_id>", methods=["DELETE"])
def delete_associated_indicator(indicator_id):
    try:
        # Fetch the indicator by ID
        indicator = associatedIndicators.query.get(indicator_id)

        # Check if the indicator exists
        if indicator is None:
            return jsonify({"error": "Associated indicator not found"}), 404

        # Delete the indicator
        db.session.delete(indicator)
        db.session.commit()

        return jsonify({"message": "Associated indicator deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "An error occurred while deleting the associated indicator",
                    "msg": str(e),
                }
            ),
            500,
        )


@app.route("/api/v1/deleteMalwareTechnical/<int:technical_id>", methods=["DELETE"])
def delete_malware_technical(technical_id):
    try:
        # Fetch the technical by ID
        technical = malwareTechnicals.query.get(technical_id)

        # Check if the technical exists
        if technical is None:
            return jsonify({"error": "Malware technical not found"}), 404

        # Delete the technical
        db.session.delete(technical)
        db.session.commit()

        return jsonify({"message": "Malware technical deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return (
            jsonify(
                {
                    "error": "An error occurred while deleting the malware technical",
                    "msg": str(e),
                }
            ),
            500,
        )


@app.route("/api/v1/newZeroDayVulnEntry", methods=["POST"])
def NewZeroDayVulnEntryAPI():
    if request.method == "POST":
        try:
            data = request.get_json()
            new_vuln = zeroDayVuln(**data)
            validation_result = new_vuln.validate_fields()
            if validation_result:
                return validation_result
            else:
                # Save the new vulnerability to the database
                db.session.add(new_vuln)
                db.session.commit()
                return (
                    jsonify(
                        {
                            "success": "New zero-day vulnerability entry added successfully"
                        }
                    ),
                    201,
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


@app.route("/api/v1/zeroDayVulns", methods=["GET"])
def get_zero_day_vulns():
    try:
        vulns = zeroDayVuln.query.all()
        serialized_vulns = extractEntries(vulns)
        return jsonify(serialized_vulns), 200
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


""" Creating Database with App Context"""


def create_db():
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    # import models
    # create_db()
    app.run(debug=True, use_reloader=False)
