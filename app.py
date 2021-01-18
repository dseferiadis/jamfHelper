from flask import Flask
from flask import Response
from werkzeug.exceptions import HTTPException
import inventory
import azure
import pandas as pd
import pathlib

app = Flask(__name__)


@app.route('/')
def default():
    return '''
        <html><body>
        Jamf Inventory <a href="/getJamfInventory/csv">CSV</a> <a href="/getJamfInventory/html">HTML</a><br>
        Lost Inventory <a href="/lostInventory/html">HTML</a><br>
        Azure Account Usage <a href="/getAzureAccountUsage/csv">CSV</a> <a href="/getAzureAccountUsage/html">HTML</a>
        </body></html>
        '''


@app.route('/getJamfInventory/csv')
def get_jamf_inventory_csv():
    return Response(
        inventory.get_inventory('csv'),
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=jamf_inventory.csv"}
    )


@app.route('/getJamfInventory/html')
def get_jamf_inventory_html():
    return Response(
        inventory.get_inventory('html')
    )


@app.route('/lostInventory/html')
def get_lost_inventory_html():
    inv_df = inventory.get_inventory('pd')
    # working_dir = str(pathlib.Path().absolute())
    # csv_file_path = working_dir + "/" + 'jamf_inventory.csv'
    # inv_df = pd.read_csv(csv_file_path)
    inv_out_df = inv_df[['IsLost', 'IsLostReason', 'name', 'model.name', 'IP_region_name', 'IP_city',
                         'DaysSinceCheckinBucket', 'DeviceValue']]
    inv_out_df = inv_out_df[inv_out_df['IsLost'] == True]
    return Response(inv_out_df.to_html()
    )


@app.route('/getAzureAccountUsage/csv')
def get_azure_account_usage_csv():
    return Response(
        azure.get_azure_account_usage('csv'),
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=jamf_inventory.csv"}
    )


@app.route('/getAzureAccountUsage/html')
def get_azure_account_usage_html():
    return Response(
        azure.get_azure_account_usage('html')
    )


@app.errorhandler(Exception)
def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e


if __name__ == '__main__':
    app.run()