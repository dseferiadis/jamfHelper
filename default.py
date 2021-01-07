from flask import Flask
from flask import Response
import main

app = Flask(__name__)


@app.route('/')
def hello_world():
    return Response(
        main.get_inventory(),
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=jamf_inventory.csv"})


if __name__ == '__main__':
    app.run()