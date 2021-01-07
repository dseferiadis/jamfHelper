# Provide the Jamf API Token from Jamf School
#
# The Username is your Jamf Network ID from Jamf School -> Devices -> Enroll Device(s) -> Number from MDM Server URL
# The Password is your API Token from Jamf School -> Organization -> Settings -> API

JamfSchoolUid = "79982428"
JamfSchoolEndpoint = "ellismarsalis.jamfcloud.com/api"
CheckInDays = 45
OutputCsvFilename = "jamf_inventory.csv"
AssignmentCsv = "assignment.csv"
OrgInitials = "EMCM"
OrgDomain = "ellismarsaliscenter.org"
DefaultEmail = "systems@ellismarsaliscenter.org"
NoteDefault = """{
"LastInventoryDate":"01-01-2019",
"LastInventoryUser":"systems@ellismarsaliscenter.org",
"AssignedTo":"systems@ellismarsaliscenter.org",
"PhysicalCondition":"Unknown",
"PhysicalLocation":"Unknown",
"Comments":""
}"""
DeviceValues = {
    "iPad4,1": "169",
    "iPad6,11": "240",
    "iPad7,11": "459",
    "iPad7,5": "200",
    "MacBook10,1": "659",
    "MacBookPro14,1": "799",
    "MacBookPro16,1": "2100",
    "MacPro7,1": "5500",
    "Parallels16,1": "0"
}