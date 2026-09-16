from flask import Flask, request,jsonify,send_from_directory
from flask_cors import CORS
import os
import pandas as pd
import io

from ml_detector import analyze_dataframe  



# ============================================================
# NETGUARD AI BACKEND
# ============================================================

app = Flask(__name__)

# Allow the frontend to communicate with Python
CORS(app)

FRONTENDED_FOLDER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontended")
)

@app.route("/")
def serve_homepage():
    return send_from_directory(
        FRONTENDED_FOLDER,
        "homepage.html"
    )

@app.route("/<path:filename>")
def serve_frontended(filename):
    return send_from_directory(
        FRONTENDED_FOLDER,
        filename
    )





# ============================================================
# ANALYZE NETWORK TRAFFIC
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        # ----------------------------------------------------
        # Receive JSON data from frontend
        # ----------------------------------------------------

        data = request.get_json()

        if not data:

            return jsonify({
                "error": "No traffic data received."
            }), 400


        # ----------------------------------------------------
        # Convert JSON into DataFrame
        # ----------------------------------------------------

        df = pd.DataFrame(data)


        if df.empty:

            return jsonify({
                "error": "Traffic dataset is empty."
            }), 400


        # ----------------------------------------------------
        # Run NetGuard detection engine
        # ----------------------------------------------------

        analysis = analyze_dataframe(df)


        # ----------------------------------------------------
        # Extract results
        # ----------------------------------------------------

        features = analysis["features"]


        # ----------------------------------------------------
        # Response sent to website
        # ----------------------------------------------------

        response = {

            "success": True,

            "system": "NetGuard AI",

            "risk": {

                "score":
                    analysis["risk_score"],

                "level":
                    analysis["threat_level"],

                "attack_type":
                    analysis["attack_type"],

                "confidence":
                    round(
                        analysis["confidence"] * 100,
                        1
                    )
            },


            "traffic": {

                "flows":
                    features["flows"],

                "packets":
                    features["packets"],

                "bytes":
                    features["bytes"],

                "unique_destinations":
                    features[
                        "unique_destinations"
                    ],

                "unique_ports":
                    features[
                        "unique_ports"
                    ],

                "average_packet_size":
                    features[
                        "average_packet_size"
                    ],

                "packets_per_flow":
                    features[
                        "packets_per_flow"
                    ]
            },


            "evidence":
                analysis["evidence"],


            "forecast": {

                "probability":
                    analysis[
                        "forecast"
                    ]["probability"],

                "predicted_stage":
                    analysis[
                        "forecast"
                    ]["predicted_stage"],

                "forecast_window":
                    analysis[
                        "forecast"
                    ]["forecast_window"]
            }

        }


        return jsonify(response)


    except Exception as error:

        print(
            "ANALYSIS ERROR:",
            str(error)
        )

        return jsonify({

            "success": False,

            "error":
                "Traffic analysis failed.",

            "details":
                str(error)

        }), 500


# ============================================================
# CSV API
# ============================================================

@app.route("/analyze-csv", methods=["POST"])
def analyze_csv():

    try:

        if "file" not in request.files:

            return jsonify({
                "error": "No CSV file uploaded."
            }), 400


        file = request.files["file"]


        if file.filename == "":

            return jsonify({
                "error": "No file selected."
            }), 400


        # Read uploaded CSV
        content = file.read()


        df = pd.read_csv(
            io.BytesIO(content)
        )


        if df.empty:

            return jsonify({
                "error": "CSV file is empty."
            }), 400


        # Run detector
        analysis = analyze_dataframe(df)


        return jsonify({

            "success": True,

            "filename":
                file.filename,

            "analysis":
                analysis

        })


    except Exception as error:

        print(
            "CSV ERROR:",
            str(error)
        )

        return jsonify({

            "success": False,

            "error":
                "CSV analysis failed.",

            "details":
                str(error)

        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({

        "status": "healthy",

        "system": "NetGuard AI",

        "detection_engine":
            "online"

    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print()
    print("=" * 55)
    print("              NETGUARD AI BACKEND")
    print("=" * 55)
    print("Status : ONLINE")
    print("Mode   : OFFLINE")
    print("Engine : Behavioral Detection")
    print("=" * 55)
    print()

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )






















































