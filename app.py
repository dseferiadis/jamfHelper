from flask import Flask
from flask import Response
from werkzeug.exceptions import HTTPException
import inventory

app = Flask(__name__)


@app.route('/')
def default():
    return '''
        <html><body>
        <a href="/getJamfInventory">Download Jamf Inventory</a>
        </body></html>
        '''


@app.route('/getJamfInventory')
def get_jamf_inventory():
    return Response(
        inventory.get_inventory(),
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=jamf_inventory.csv"})


@app.errorhandler(Exception)
def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e


if __name__ == '__main__':
    app.run()