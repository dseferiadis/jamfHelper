# Import Modules
import config
import requests
from requests.auth import HTTPBasicAuth
import json
import datetime
import re
import pathlib
import pandas as pd
import os

# Import Variables
JamfSchoolUid = config.JamfSchoolUid
JAMF_SCHOOL_PWD = os.getenv('JAMF_SCHOOL_PWD')
JamfSchoolEndpoint = config.JamfSchoolEndpoint
CheckInDays = config.CheckInDays
OutputCsvFilename = config.OutputCsvFilename
AssignmentCsv = config.AssignmentCsv
OrgInitials = config.OrgInitials
NoteDefault = config.NoteDefault
GEO_API_KEY = os.getenv('GEO_API_KEY')
DeviceValues = config.DeviceValues

# Defime Geo Location Lookup Cache
geo_ip_lookup_cache = {}


def update_needed(df_target_versions, modelid, os_version):
    # Parse Version String into Major, Minor and Bug Release
    # Newest OS version for model ID is assumed to be target version that others must upgrade to
    regex = '(\\d+)(\\.)(\\d+)(\\.)(\\d+)'
    os_version_search = re.search(regex, os_version, re.IGNORECASE)

    if os_version_search:
        os_major = os_version_search.group(1)
        os_minor = os_version_search.group(3)
        os_patch = os_version_search.group(5)
    else:
        return False

    os_major_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_major'][0]
    os_minor_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_minor'][0]
    os_patch_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_patch'][0]

    if os_major < os_major_current or \
            (os_major == os_major_current and os_minor < os_minor_current) or \
            (os_major == os_major_current and os_minor == os_minor_current and os_patch < os_patch_current):
        return True
    else:
        return False


def get_target_os(jsondevices):
    # Determine Newest OS for each Model ID that will be target state
    df_version_cols = ["model", "os_major", "os_minor", "os_patch"]
    df_target_versions = pd.DataFrame(columns=df_version_cols)

    for device in jsondevices["devices"]:
        modelid = device["model"]["identifier"]

        # Parse Version String into Major, Minor and Bug Release
        regex = '(\\d+)(\\.)(\\d+)(\\.)(\\d+)'
        os_version_search = re.search(regex, device["os"]["version"], re.IGNORECASE)

        if os_version_search:
            os_major = os_version_search.group(1)
            os_minor = os_version_search.group(3)
            os_patch = os_version_search.group(5)
        else:
            return False

        # Prepare new Dataframe Row
        version_row = [[device["model"]["identifier"], os_major, os_minor, os_patch]]
        df_version_row = pd.DataFrame(version_row, columns=df_version_cols)

        # Add row if no entry exists for this model
        if not df_target_versions['model'].str.contains(modelid).any():
            df_target_versions = df_target_versions.append(df_version_row)

        # Update Row if Entry Already Exists for model and we found a newer version
        else:
            os_major_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_major'][0]
            os_minor_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_minor'][0]
            os_patch_current = df_target_versions.loc[df_target_versions['model'] == modelid, 'os_patch'][0]

            if os_major > os_major_current or \
                    (os_major == os_major_current and os_minor > os_minor_current) or \
                    (os_major == os_major_current and os_minor == os_minor_current and os_patch > os_patch_current):

                df_target_versions.loc[df_target_versions['model'] == modelid, 'os_major'] = os_major
                df_target_versions.loc[df_target_versions['model'] == modelid, 'os_minor'] = os_minor
                df_target_versions.loc[df_target_versions['model'] == modelid, 'os_patch'] = os_patch
    return df_target_versions


def naming_convention(name, isvirtual, modeltype):
    # Validate Naming Convention Matches Target Convention
    result = {
        "NameInConvention": "Unknown",
        "NameInConventionReason": "Default"
    }

    if isvirtual:
        min_range = 9900
        max_range = 9999
        device_type = "Virtual"
        prefix = "V"
        regex = OrgInitials + prefix + '(\\d{4})'
        search_result = re.search(regex, name, re.IGNORECASE)
        if search_result:
            device_num = int(search_result.group(1))
            if min_range <= device_num <= max_range:
                result["NameInConvention"] = "True"
                result["NameInConventionReason"] = "Base name is in alignment and number is between " + \
                                                   str(min_range) + " and " + str(max_range)
            else:
                result["NameInConvention"] = "False"
                result["NameInConventionReason"] = "Base name is in alignment but number is not between " + \
                                                   str(min_range) + " and " + str(max_range)
            return result
        else:
            result["NameInConvention"] = "False"
            result["NameInConventionReason"] = "Base name is not in alignment for " + device_type + ": " + \
                                               OrgInitials + prefix + "(" + str(min_range) + "-" + str(max_range) + ")"
        return result
    elif modeltype == "MacBook" or modeltype == "MacBook Pro":
        min_range = 8000
        max_range = 9499
        device_type = "MacBook / MacBook Pro"
        prefix = "MB"
        regex = OrgInitials + prefix + '(\\d{4})'
        search_result = re.search(regex, name, re.IGNORECASE)
        if search_result:
            device_num = int(search_result.group(1))
            if min_range <= device_num <= max_range:
                result["NameInConvention"] = "True"
                result["NameInConventionReason"] = "Base name is in alignment and number is between " + \
                                                   str(min_range) + " and " + str(max_range)
            else:
                result["NameInConvention"] = "False"
                result["NameInConventionReason"] = "Base name is in alignment but number is not between " + \
                                                   str(min_range) + " and " + str(max_range)
            return result
        else:
            result["NameInConvention"] = "False"
            result["NameInConventionReason"] = "Base name is not in alignment for " + device_type + ": " + \
                                               OrgInitials + prefix + "(" + str(min_range) + "-" + str(max_range) + ")"
        return result
    elif modeltype == "Mac Pro":
        min_range = 9800
        max_range = 9899
        device_type = "Mac Pro"
        prefix = "MP"
        regex = OrgInitials + prefix + '(\\d{4})'
        search_result = re.search(regex, name, re.IGNORECASE)
        if search_result:
            device_num = int(search_result.group(1))
            if min_range <= device_num <= max_range:
                result["NameInConvention"] = "True"
                result["NameInConventionReason"] = "Base name is in alignment and number is between " + \
                                                   str(min_range) + " and " + str(max_range)
            else:
                result["NameInConvention"] = "False"
                result["NameInConventionReason"] = "Base name is in alignment but number is not between " + \
                                                   str(min_range) + " and " + str(max_range)
            return result
        else:
            result["NameInConvention"] = "False"
            result["NameInConventionReason"] = "Base name is not in alignment for " + device_type + ": " + \
                                               OrgInitials + prefix + "(" + str(min_range) + "-" + str(max_range) + ")"
        return result
    elif modeltype == "iPad":
        min_range = 1
        max_range = 7999
        device_type = "iPad"
        prefix = "I"
        regex = OrgInitials + prefix + '(\\d{4})'
        search_result = re.search(regex, name, re.IGNORECASE)
        if search_result:
            device_num = int(search_result.group(1))
            if min_range <= device_num <= max_range:
                result["NameInConvention"] = "True"
                result["NameInConventionReason"] = "Base name is in alignment and number is between " + \
                                                   str(min_range) + " and " + str(max_range)
            else:
                result["NameInConvention"] = "False"
                result["NameInConventionReason"] = "Base name is in alignment but number is not between " + \
                                                   str(min_range) + " and " + str(max_range)
            return result
        else:
            result["NameInConvention"] = "False"
            result["NameInConventionReason"] = "Base name is not in alignment for " + device_type + ": " + \
                                               OrgInitials + prefix + "(" + str(min_range) + "-" + str(max_range) + ")"
        return result


def get_user_email(firstname, lastname, usertype, orgdomain):
    # Strip Leading and Trailing Whitespace
    firstname = firstname.strip()
    lastname = lastname.strip()

    # Convert to Lowercase
    firstname = firstname.lower()
    lastname = lastname.lower()

    # Remove any non-word characters
    firstname = re.sub(r'\W', '', firstname)
    lastname = re.sub(r'\W', '', lastname)

    # Concatenate Email Suffix
    email_suffix = "@" + usertype + "." + orgdomain

    # Ensure names are at least one character
    if len(firstname) > 0 and len(lastname) > 0 and len(usertype) > 0 and len(orgdomain):
        return firstname + "." + lastname + email_suffix
    else:
        return None


# Update Notes Object
def get_assigned_user(serial, current_value):
    # Check Serial Number to Email Address Assignment List to Determine who Device was Assigned to

    # If Serial Number is not matched in assignment sheet, then validate current assignment email
    return validate_email(current_value)


# Update Notes Object
def update_notes(udid, notes_json):
    notes_json_withkey = {'notes': json.dumps(notes_json)}
    input("Press enter to update notes...")
    target_url = 'https://' + JamfSchoolEndpoint + '/devices/' + udid + '/details'
    response = requests.post(target_url, notes_json_withkey,
                             auth=HTTPBasicAuth(JamfSchoolUid, JAMF_SCHOOL_PWD))
    if not response.status_code == 200:
        print("Error Updating: ", response)
        input("Press enter to continue...")


# Verify JSON Object
def is_json(my_json):
    try:
        json.loads(my_json)
    except ValueError as my_json_e:
        print(my_json_e)
        return False
    return True


# Validate user assignments and ensure they are email addresses
def validate_email(email):
    regex = r'^[\S]+[\._]?[\S]+[@][\w\.]+[.]\w{2,3}$'
    if re.search(regex, email):
        return email
    else:
        print("Invalid Email:", email)
        return config.DefaultEmail


# Get Days Since Last Inventory
def get_days_since_last_iventory(note):
    note_json = json.loads(note)
    for nkey, nvalue in note_json.items():
        if nkey == "LastInventoryDate":
            deltadayslastinventory = datetime.datetime.now() - datetime.datetime.strptime(nvalue, '%m-%d-%Y')
            return deltadayslastinventory.days
    # Return Error Value if we didn't find LastInventoryDate
    return -1


# Get Sublocations from Notes Data
def get_sublocations(note):
    note_json = json.loads(note)
    result = []
    for nkey, nvalue in note_json.items():
        if nkey == "PhysicalLocation":
            locsearch = re.search('(EMCM)(BoxedSlot)(\\d+)', nvalue, re.IGNORECASE)
            if locsearch:
                result.append(locsearch.group(1))
                result.append(locsearch.group(2))
                result.append(locsearch.group(3))
                return result
            locsearch = re.search('(EMCM)(Cart\\d+Slot)(\\d+)', nvalue, re.IGNORECASE)
            if locsearch:
                result.append(locsearch.group(1))
                result.append(locsearch.group(2))
                result.append(locsearch.group(3))
                return result
            # Default Response if Patten is not matched
            result.append(nvalue)
            return result
    # Return Error Value if we didn't find LastInventoryDate
    return -1


# Get Geo Location Based on Last Reported IP Address
def get_ip_geolocation(ip_address):
    # Check if Cache has already looked up this IP
    if ip_address not in geo_ip_lookup_cache.keys():
        geo_location = (requests.get("http://api.ipstack.com/" + ip_address + "?access_key=" +
                                     GEO_API_KEY + "&hostname=1")).json()
        # Exception for Known IP Addresses
        if ip_address == "72.214.117.2":
            geo_location["city"] = "New Orleans - EMCM"
            geo_location["zip"] = "70117"
        geo_ip_lookup_cache[ip_address] = geo_location
    # Always return content from cache
    return geo_ip_lookup_cache[ip_address]


# Validate JSON Fields Match Template
def notes_is_valid(udid, serial, notedefault, note):
    # Validated JSON in Notes Field and returns True if notes is valid and no updates required
    note_json = json.loads(note)
    notedefault_json = json.loads(notedefault)
    clean_dict = {}

    # Check to make sure all JSON keys are valid and exist in default template
    for nkey, nvalue in note_json.items():
        key_valid = False
        for dkey, dvalue in notedefault_json.items():
            if nkey == dkey:
                key_valid = True
                if nkey == "LastInventoryUser":
                    nvalue = validate_email(nvalue)
                if nkey == "AssignedTo":
                    nvalue = get_assigned_user(serial, nvalue)
                clean_dict[nkey] = nvalue
                break
        if not key_valid:
            print("     Key not found in default template: " + nkey)

    # Check to make sure all keys in default template are in notes JSON
    for dkey, dvalue in notedefault_json.items():
        key_valid = False
        for nkey, nvalue in note_json.items():
            if dkey == nkey:
                key_valid = True
                break
        if not key_valid:
            print("     Key from default template not found in notes: " + dkey)
            clean_dict[dkey] = dvalue

    if not note_json == clean_dict:
        print("Updating Notes")
        print("Default:", notedefault_json)
        print("Before :", note_json)
        print("After  :", clean_dict)
        update_notes(udid, clean_dict)
        return False
    else:
        return True


# Validate Device Name is Unique
def is_device_name_unique(name, jsondevices):
    device_count = 0

    for device in jsondevices["devices"]:
        if name.lower() == device["name"].lower():
            device_count = device_count + 1
            if device_count > 1:
                return False
    return True


# Determine Potentially Lost Status
def get_is_lost(is_virtual, days, ip_city, assigned_to):
    result = {
        "IsLost": "Unknown",
        "IsLostReason": "Default"
    }

    # If device has not reported to Jamf in more than CheckInDays
    if is_virtual:
        result["IsLost"] = "False"
        result["IsLostReason"] = "Virtual devices are not tracked"
        return result
    elif days > days:
        result["IsLost"] = "True"
        result["IsLostReason"] = "Device has not checked in within " + str(CheckInDays) + " days"
        return result
    elif ip_city != "New Orleans - EMCM" and assigned_to == "systems@ellismarsaliscenter.org":
        # If devices is online + not using EMCM IP address + not assigned to user / user not validated
        result["IsLost"] = "True"
        result["IsLostReason"] = "Device is reported outside EMCM and not assigned to user"
        return result
    else:
        result["IsLost"] = "False"
        result["IsLostReason"] = "Device has reported to Jamf within " + str(CheckInDays) + \
                                 " days and is at EMCM or it is assigned to a user"
        return result


def get_days_since_checkin_bucket(days):
    # Report Summary Date Buckets for Simlified Reporting
    if days <= 1:
        return "0-1 days"
    elif days <= 7:
        return "2-7 days"
    elif days <= 45:
        return "8-45 days"
    else:
        return ">45 days"


def get_inventory_needed(days):
    # Report if inventory is due for devices
    if days > CheckInDays:
        return True
    else:
        return False


# Start Main Logic
def get_inventory(output_format):
    print("Starting Jamf Management")
    print("Current Working Directory", pathlib.Path().absolute())
    refresh_needed = False

    # Get Devices in Jamf
    devices = requests.get('https://' + JamfSchoolEndpoint + '/devices',
                           auth=HTTPBasicAuth(JamfSchoolUid, JAMF_SCHOOL_PWD))
    json_devices = devices.json()

    # Get Target OS Versions for Device Types
    target_os = get_target_os(json_devices)

    # Create Metadata Enrichment Dataframe
    df_column_names = ["name", "IsVirtual", "NameInConvention", "UpdateNeeded", "NameUnique", "DaysSinceCheckin",
                       "DaysSinceLastInventory", "LocationTier0", "LocationTier1", "LocationTier2", "IP_region_name",
                       "IP_city", "IP_zip", "IP_hostname", "IsLost", "IsLostReason", "DaysSinceCheckinBucket",
                       "DeviceValue", "InventoryNeeded", "NameInConventionReason"]
    df_metadata = pd.DataFrame(columns=df_column_names)

    # Process List of Devices
    print("Looping through Device List")
    for row in json_devices["devices"]:
        print(" ", row["name"])

        # Check if Device Type is Physical or Virtual
        is_virtual = False
        if "model" in row:
            for key, value in row["model"].items():
                # print(key, value)
                if key == 'identifier' and 'Parallels1'.lower() in value.lower():
                    is_virtual = True
                    break

        # Compute Days Since Last Checkin
        last_checkin = row["lastCheckin"]
        last_checkin = datetime.datetime.strptime(last_checkin, '%Y-%m-%d %H:%M:%S')
        current_time = datetime.datetime.now()
        delta = current_time - last_checkin
        days_since_checkin = delta.days

        # Check Notes Field to Determine Status
        update_required = 0
        if "notes" in row:
            notes_json = row["notes"]
            # If data exists in notes field attempt to evaluate
            if len(notes_json) == 0:
                # Populate Default JSON Template
                print("   Populating Default JSON Notes")
                notes_json = json.loads(NoteDefault)
                update_required = update_required + 1
            elif len(notes_json) > 0:
                # If JSON content is not valid - attempt to correct
                if not is_json(notes_json):
                    return row["name"] + " notes is is not a valid JSON Object"
                else:
                    if notes_is_valid(row["UDID"], row["serialNumber"], NoteDefault, notes_json) is False:
                        refresh_needed = True
                        continue
            if update_required > 0:
                update_notes(row["UDID"], notes_json)
                refresh_needed = True
                continue

        # Check if Naming Convention Matches
        naming_standard = naming_convention(row["name"], is_virtual, row["model"]["type"])

        # Check if Update Needed
        device_update_needed = update_needed(target_os, row["model"]["identifier"], row["os"]["version"])

        # Check if Device Name is Unique
        device_unique_name = is_device_name_unique(row["name"], devices.json())

        # Get Days Since Last Inventory from Notes JSON
        days_since_last_inventory = get_days_since_last_iventory(row["notes"])

        # Parse Location fied Sublocation Tiers
        sublocations = get_sublocations(row["notes"])
        location_tier_0 = ""
        location_tier_1 = ""
        location_tier_2 = ""
        if len(sublocations) > 0:
            location_tier_0 = sublocations[0]
        if len(sublocations) > 1:
            location_tier_1 = sublocations[1]
        if len(sublocations) > 2:
            location_tier_2 = sublocations[2]

        # Get Geolocation of IP Address
        json_geo_location = get_ip_geolocation(row["networkInformation"]["IPAddress"])

        # Get Lost Status row["notes"]["AssignedTo"]
        islost = get_is_lost(is_virtual, days_since_checkin, json_geo_location["city"],
                             json.loads(row["notes"])["AssignedTo"])

        # Get Days Since Checkin Bucket
        days_since_checkin_bucket = get_days_since_checkin_bucket(days_since_checkin)

        # Get Device Value
        device_value = DeviceValues[row["model"]["identifier"]]

        # Determine if Inventory is Needed
        inventory_needed = get_inventory_needed(days_since_last_inventory)

        # Update Metadata DataFrame with Reference Data
        metadata_row = [[row["name"], is_virtual, naming_standard["NameInConvention"], device_update_needed,
                         device_unique_name, days_since_checkin, days_since_last_inventory, location_tier_0,
                         location_tier_1, location_tier_2, json_geo_location["region_name"], json_geo_location["city"],
                         json_geo_location["zip"], json_geo_location["hostname"], islost["IsLost"],
                         islost["IsLostReason"], days_since_checkin_bucket, device_value, inventory_needed,
                         naming_standard["NameInConventionReason"]]]
        df_metadata_row = pd.DataFrame(metadata_row, columns=df_column_names)
        df_metadata = df_metadata.append(df_metadata_row)

    if refresh_needed:
        print("Updates to JSON made during this cycle, must refresh again before exporting results")
        return get_inventory(output_format)

    # Remove Secondary JSON Encapsulated of Notes
    rownum = -1
    devicename = ""
    try:
        for row in json_devices["devices"]:
            devicename = row["name"]
            rownum = rownum + 1
            if "notes" in row:
                json_devices["devices"][rownum]["notes"] = json.loads(row["notes"])
    except ValueError as e:
        return "Removing Secondary JSON Encapsulation Failed on" + devicename + " (" + str(e) + ")"

    # Flatten JSON to Prepare for Output to CSV
    df = pd.json_normalize(json_devices["devices"])

    # Join JAMF Data with Derived Metadata
    df = pd.merge(df, df_metadata, how='outer', left_on='name', right_on='name')

    print("")
    print("Execution Complete")
    if output_format == "csv":
        return df.to_csv(index=False)
    elif output_format == "html":
        return df.to_html()
    elif output_format == "pd":
        return df
    else:
        return df