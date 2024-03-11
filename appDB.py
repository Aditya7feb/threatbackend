""" database.py file """
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify

""" SQLAlchemy Instance """
db = SQLAlchemy()

# class newMalwareThreats(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     malwareName = db.Column(db.Text, nullable = False)
#     recordDate = db.Column(db.DateTime, nullable = False)
#     category = db.Column(db.Text, nullable = False)
#     description = db.Column(db.Text, nullable = False)
#     ttp = db.Column(db.Text, nullable = False)
#     associatedThreatActors = db.Column(db.Text, nullable = False)
#     attackVectors = db.Column(db.Text, nullable = False)
#     associatedVulns = db.Column(db.Text, nullable = False)
#     remarks = db.Column(db.Text, nullable = True)

#     def __init__(self, malwarename, recorddate, category, description, ttp, associatedthreatactors, attackvectors, associatedvulns):
#         self.malwarename = malwarename
#         self.recorddate = recorddate
#         self.category = category
#         self.description = description
#         self.ttp = ttp
#         self.associatedthreatactors = associatedthreatactors
#         self.attackvectors = attackvectors
#         self.associatedvulns = associatedvulns

# class malwareTechnicals(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     technicalSummary = db.Column(db.Text, nullable = False)
#     referenceLinks = db.Column(db.Text, nullable = False)
#     imageHeading = db.Column(db.Text, nullable = False)
#     imageLink = db.Column(db.Text, nullable = False)

#     def __init__(self, technicalSummary, referenceLinks, imageHeading, imageLink):
#         self.technicalSummary = technicalSummary
#         self.referenceLinks = referenceLinks
#         self.imageHeading = imageHeading
#         self.imageLink = imageLink

# class associatedIndicators(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     ip = db.Column(db.Text, nullable = False)
#     domains = db.Column(db.Text, nullable = False)
#     hashes = db.Column(db.Text, nullable = False)

#     def __init__(self, ip, domains, hashes):
#         self.ip = ip
#         self.domains = domains
#         self.hashes = hashes


class malwareThreats(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    malwareName = db.Column(db.Text, nullable=False, unique=True)
    recordDate = db.Column(db.String(50), nullable=False)
    category = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    ttp = db.Column(db.Text, nullable=False)
    associatedThreatActors = db.Column(db.Text, nullable=False)
    attackVectors = db.Column(db.Text, nullable=False)
    associatedVulns = db.Column(db.Text, nullable=False)
    remarks = db.Column(db.Text, nullable=True)

    # Define the relationship with malwareTechnicals
    technicals = db.relationship(
        "malwareTechnicals", backref="malwareThreat", uselist=False
    )

    # Define the relationship with associatedIndicators
    indicators = db.relationship(
        "associatedIndicators", backref="malwareThreat", uselist=True
    )

    def __init__(
        self,
        malwareName,
        recordDate,
        category,
        description,
        ttp,
        associatedThreatActors,
        attackVectors,
        associatedVulns,
        remarks,
    ):
        self.malwareName = malwareName
        self.recordDate = recordDate
        self.category = category
        self.description = description
        self.ttp = ttp
        self.associatedThreatActors = associatedThreatActors
        self.attackVectors = attackVectors
        self.associatedVulns = associatedVulns
        self.remarks = remarks

    def validate_fields(self):
        errors = {}
        if not self.malwareName:
            errors["malwareName"] = "Malware name is required."
        if not self.recordDate:
            errors["recordDate"] = "Record date is required."
        if not self.category:
            errors["category"] = "Category is required."
        if not self.description:
            errors["description"] = "Description is required."
        if not self.ttp:
            errors["ttp"] = "TTP is required."
        if not self.associatedThreatActors:
            errors["associatedThreatActors"] = "Associated threat actors are required."
        if not self.attackVectors:
            errors["attackVectors"] = "Attack vectors are required."
        if not self.associatedVulns:
            errors["associatedVulns"] = "Associated vulnerabilities are required."
        if not self.remarks:
            errors["remarks"] = "Remarks are required."

        if errors:
            return jsonify({"error": "Validation failed", "errors": errors}), 400
        else:
            return None


class malwareTechnicals(db.Model):
    autoID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    malware_threat_id = db.Column(
        db.Integer, db.ForeignKey("malware_threats.id"), nullable=False
    )
    technicalSummary = db.Column(db.Text, nullable=False)
    referenceLinks = db.Column(db.Text, nullable=False)
    imageHeading = db.Column(db.Text, nullable=False)
    imageLink = db.Column(db.Text, nullable=False)

    def __init__(
        self,
        malware_threat_id,
        technicalSummary,
        referenceLinks,
        imageHeading,
        imageLink,
    ):
        self.malware_threat_id = malware_threat_id
        self.technicalSummary = technicalSummary
        self.referenceLinks = referenceLinks
        self.imageHeading = imageHeading
        self.imageLink = imageLink

    def validate_fields(self):
        errors = {}
        if not self.malware_threat_id:
            errors["malware_threat_id"] = "Malware threat ID is required."
        if not self.technicalSummary:
            errors["technicalSummary"] = "Technical summary is required."
        if not self.referenceLinks:
            errors["referenceLinks"] = "Reference links are required."
        if not self.imageHeading:
            errors["imageHeading"] = "Image heading is required."
        if not self.imageLink:
            errors["imageLink"] = "Image link is required."

        if errors:
            return jsonify({"error": "Validation failed", "errors": errors}), 400
        else:
            return None


class associatedIndicators(db.Model):
    autoID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    malware_threat_id = db.Column(
        db.Integer, db.ForeignKey("malware_threats.id"), nullable=False
    )
    ip = db.Column(db.Text, nullable=False)
    domains = db.Column(db.Text, nullable=False)
    hashes = db.Column(db.Text, nullable=False)

    def __init__(self, malware_threat_id, ip, domains, hashes):
        self.malware_threat_id = malware_threat_id
        self.ip = ip
        self.domains = domains
        self.hashes = hashes

    def validate_fields(self):
        errors = {}
        if not self.ip:
            errors["ip"] = "IP address is required."
        if not self.domains:
            errors["domains"] = "Domains are required."
        if not self.hashes:
            errors["hashes"] = "Hashes are required."

        if errors:
            return jsonify({"error": "Validation failed", "errors": errors}), 400
        else:
            return None


class zeroDayVuln(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    updatedOn = db.Column(db.String(50), nullable=False)
    cveIdentifier = db.Column(db.Text, nullable=True, unique=True)
    relatedCVEIdentifier = db.Column(db.Text, nullable=True)
    firstReferenced = db.Column(db.String(50), nullable=True)
    confHits30DaysInstance = db.Column(db.Integer, nullable=True)
    confHits30DaysAsset = db.Column(db.Integer, nullable=True)
    trend = db.Column(db.Text, nullable=True)
    isZeroDay = db.Column(db.Boolean, nullable=False)
    aiftThreatIntelSummary = db.Column(db.Text, nullable=True)
    nvdSummary = db.Column(db.Text, nullable=True)
    severity = db.Column(db.Text, nullable=True)
    affectedProducts = db.Column(db.Text, nullable=True)
    pocAvailaibility = db.Column(db.Boolean, nullable=False)
    attackVector = db.Column(db.Text, nullable=True)
    associatedThreatActors = db.Column(db.Text, nullable=True)
    associatedMalware = db.Column(db.Text, nullable=True)
    reviewedBySOC = db.Column(db.Boolean, nullable=True)
    referenceLinks = db.Column(db.Text, nullable=True)

    def __init__(
        self,
        updatedOn,
        cveIdentifier,
        relatedCVEIdentifier,
        firstReferenced,
        confHits30DaysInstance,
        confHits30DaysAsset,
        trend,
        isZeroDay,
        aiftThreatIntelSummary,
        nvdSummary,
        severity,
        affectedProducts,
        pocAvailaibility,
        attackVector,
        associatedThreatActors,
        associatedMalware,
        reviewedBySOC,
        referenceLinks,
    ):
        self.updatedOn = updatedOn
        self.cveIdentifier = cveIdentifier
        self.relatedCVEIdentifier = relatedCVEIdentifier
        self.firstReferenced = firstReferenced
        self.confHits30DaysInstance = confHits30DaysInstance
        self.confHits30DaysAsset = confHits30DaysAsset
        self.trend = trend
        self.isZeroDay = isZeroDay
        self.aiftThreatIntelSummary = aiftThreatIntelSummary
        self.nvdSummary = nvdSummary
        self.severity = severity
        self.affectedProducts = affectedProducts
        self.pocAvailaibility = pocAvailaibility
        self.attackVector = attackVector
        self.associatedThreatActors = associatedThreatActors
        self.associatedMalware = associatedMalware
        self.reviewedBySOC = reviewedBySOC
        self.referenceLinks = referenceLinks

    def validate_fields(self):
        errors = {}
        if not self.isZeroDay:
            errors["isZeroDay"] = "isZeroDay is required."
        if not self.relatedCVEIdentifier:
            errors["pocAvailaibility"] = "pocAvailaibility Identifier is required."

        if errors:
            return jsonify({"error": "Validation failed", "errors": errors}), 400
        else:
            return None
