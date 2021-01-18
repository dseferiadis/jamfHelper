import requests
import json
import pandas as pd
import datetime
import pytz
import pathlib
import os

AZURE_TENANT = "ellismarsaliscenter.org"
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')


def get_ms_graph_access_token():
    url = 'https://login.microsoftonline.com/' + AZURE_TENANT + '/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': AZURE_CLIENT_ID,
        'client_secret': AZURE_CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    token_r = requests.post(url, data=token_data)
    token = token_r.json().get('access_token')
    return token


def get_azure_users(token, pagesize):
    # Using Beta Endpoint since this returns the last login date
    users_url = "https://graph.microsoft.com/beta/users"
    headers = {'Authorization': 'Bearer ' + token}
    params = {'$top': pagesize,
              '$select': 'userPrincipalName,jobTitle,signInActivity'}
    user_response_data = json.loads(requests.get(users_url, headers=headers, params=params).text)
    users_df = pd.DataFrame(data=user_response_data['value'])
    while '@odata.nextLink' in user_response_data:
        users_url = user_response_data['@odata.nextLink']
        user_response_data = json.loads(requests.get(users_url, headers=headers).text)
        users_df_temp = pd.DataFrame(data=user_response_data['value'])
        users_df = users_df.append(users_df_temp)
    return users_df


def get_azure_user_signins(token, pagesize, upn):
    signins_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    headers = {'Authorization': 'Bearer ' + token}
    filter_text = "userPrincipalName eq '" + upn + "'"
    params = {'$filter': filter_text}
    user_response_data = json.loads(requests.get(signins_url, headers=headers, params=params).text)
    sign_in_events = 0
    try:
        sign_in_events = len(user_response_data['value'])
    except:
        sign_in_events = 0

    if sign_in_events > 0:
        sign_ins_df = pd.DataFrame(data=user_response_data['value'])
        while '@odata.nextLink' in user_response_data:
            signins_url = user_response_data['@odata.nextLink']
            user_response_data = json.loads(requests.get(signins_url, headers=headers).text)
            sign_ins_df_temp = pd.DataFrame(data=user_response_data['value'])
            sign_ins_df = sign_ins_df.append(sign_ins_df_temp)
        return sign_ins_df
    else:
        return None


def get_azure_account_usage(output_format):
    # Connect to Microsoft Graph and Get Usage Data
    aad_token = get_ms_graph_access_token()
    azure_users = get_azure_users(aad_token, 50)

    df_column_names = ["userPrincipalName", "jobTitle", "LastLoginDays", "SignInEvents"]
    df_results = pd.DataFrame(columns=df_column_names)

    for index, row in azure_users.iterrows():
        upn = row['userPrincipalName']
        print(upn)

        # Subquery to get Azure AD Login Activity
        user_signins = get_azure_user_signins(aad_token, 50, upn)
        signin_qty = 0
        if user_signins is not None:
            signin_qty = user_signins.shape[0]
            print("   " + str(signin_qty) + " sign-in events!")

        # Get Job Title
        user_title = row['jobTitle']

        # Get Last Login Data
        days_since_login = -1
        if 'signInActivity' in row:
            if pd.isnull(row['signInActivity']) is not True:
                if pd.isnull(row['signInActivity']['lastSignInDateTime']) is not True:
                    lastsignindatetime = pd.to_datetime(row['signInActivity']['lastSignInDateTime'])
                    current_time = datetime.datetime.utcnow()
                    current_time = current_time.replace(tzinfo=pytz.utc)
                    deltadays = current_time - lastsignindatetime
                    days_since_login = deltadays.days
                    print("   Last Login " + str(days_since_login) + " day(s) ago at " + str(lastsignindatetime))
        else:
            print("   Never Logged Into")

        # Update Metadata DataFrame with Reference Data
        results_row = [[upn, user_title, days_since_login, signin_qty]]
        df_results_row = pd.DataFrame(results_row, columns=df_column_names)
        df_results = df_results.append(df_results_row)

    if output_format == "csv":
        return df_results.to_csv(index=False)
    elif output_format == "html":
        return df_results.to_html(index=False)
    elif output_format == "pd":
        return df_results
    else:
        return df_results
