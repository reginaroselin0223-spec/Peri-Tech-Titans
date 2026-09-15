import pandas as pd
import numpy as np


# ============================================================
# NETGUARD AI - TRAFFIC DETECTION ENGINE
# ============================================================

class NetGuardDetector:

    def __init__(self):
        self.name = "NetGuard Behavioral Detection Engine"

    # --------------------------------------------------------
    # Convert values safely to numbers
    # --------------------------------------------------------

    def _number(self, value, default=0):

        try:
            if pd.isna(value):
                return default

            return float(value)

        except Exception:
            return default

    # --------------------------------------------------------
    # Find a column even if its name is slightly different
    # --------------------------------------------------------

    def _find_column(self, dataframe, possible_names):

        columns = {
            str(column).lower().strip(): column
            for column in dataframe.columns
        }

        for name in possible_names:

            if name.lower() in columns:
                return columns[name.lower()]

        return None

    # --------------------------------------------------------
    # Extract security features
    # --------------------------------------------------------

    def extract_features(self, dataframe):

        df = dataframe.copy()

        # Number of flows
        flows = len(df)

        # ----------------------------------------------------
        # Packet count
        # ----------------------------------------------------

        packet_column = self._find_column(
            df,
            [
                "packets",
                "packet_count",
                "total_packets",
                "tot_fwd_packets",
                "fwd_packets"
            ]
        )

        if packet_column:

            packets = pd.to_numeric(
                df[packet_column],
                errors="coerce"
            ).fillna(0).sum()

        else:

            packets = 0


        # ----------------------------------------------------
        # Bytes
        # ----------------------------------------------------

        byte_column = self._find_column(
            df,
            [
                "bytes",
                "total_bytes",
                "byte_count",
                "totlen",
                "total_length"
            ]
        )

        if byte_column:

            total_bytes = pd.to_numeric(
                df[byte_column],
                errors="coerce"
            ).fillna(0).sum()

        else:

            total_bytes = 0


        # ----------------------------------------------------
        # Destination IP
        # ----------------------------------------------------

        destination_column = self._find_column(
            df,
            [
                "destination_ip",
                "dst_ip",
                "destination",
                "dst"
            ]
        )

        if destination_column:

            unique_destinations = (
                df[destination_column]
                .astype(str)
                .nunique()
            )

        else:

            unique_destinations = 0


        # ----------------------------------------------------
        # Destination port
        # ----------------------------------------------------

        port_column = self._find_column(
            df,
            [
                "destination_port",
                "dst_port",
                "dest_port",
                "port"
            ]
        )

        if port_column:

            unique_ports = (
                pd.to_numeric(
                    df[port_column],
                    errors="coerce"
                )
                .dropna()
                .nunique()
            )

        else:

            unique_ports = 0


        # ----------------------------------------------------
        # Average packet size
        # ----------------------------------------------------

        if packets > 0:

            average_packet_size = (
                total_bytes / packets
            )

        else:

            average_packet_size = 0


        # ----------------------------------------------------
        # Packets per flow
        # ----------------------------------------------------

        if flows > 0:

            packets_per_flow = packets / flows

        else:

            packets_per_flow = 0


        return {

            "flows": int(flows),

            "packets": int(packets),

            "bytes": int(total_bytes),

            "unique_destinations":
                int(unique_destinations),

            "unique_ports":
                int(unique_ports),

            "average_packet_size":
                round(average_packet_size, 2),

            "packets_per_flow":
                round(packets_per_flow, 2)
        }


    # --------------------------------------------------------
    # Behavioral threat analysis
    # --------------------------------------------------------

    def detect(self, dataframe):

        features = self.extract_features(
            dataframe
        )


        score = 0

        evidence = []

        attack_type = "BENIGN"

        # ====================================================
        # RECONNAISSANCE / PORT SCANNING
        # ====================================================

        if features["unique_ports"] >= 20:

            score += 35

            evidence.append(
                "Large number of destination ports observed"
            )

            attack_type = "PORT SCAN"


        # ====================================================
        # HIGH DESTINATION SCANNING
        # ====================================================

        if features["unique_destinations"] >= 20:

            score += 25

            evidence.append(
                "Traffic reaches many destination hosts"
            )

            if attack_type == "BENIGN":

                attack_type = "NETWORK RECONNAISSANCE"


        # ====================================================
        # HIGH PACKET VOLUME
        # ====================================================

        if features["packets"] >= 10000:

            score += 25

            evidence.append(
                "Unusually high packet volume detected"
            )

            if attack_type == "BENIGN":

                attack_type = "HIGH VOLUME TRAFFIC"


        # ====================================================
        # HIGH FLOW COUNT
        # ====================================================

        if features["flows"] >= 1000:

            score += 20

            evidence.append(
                "Large number of network flows detected"
            )

            if attack_type == "BENIGN":

                attack_type = "FLOW FLOODING"


        # ====================================================
        # VERY SMALL AVERAGE PACKETS
        # ====================================================

        if (
            features["average_packet_size"] > 0
            and
            features["average_packet_size"] < 80
        ):

            score += 10

            evidence.append(
                "Very small average packet size"
            )


        # ====================================================
        # VERY HIGH PACKETS PER FLOW
        # ====================================================

        if features["packets_per_flow"] >= 100:

            score += 10

            evidence.append(
                "High packet concentration per flow"
            )


        # ====================================================
        # CAP SCORE
        # ====================================================

        score = min(score, 100)


        # ====================================================
        # THREAT LEVEL
        # ====================================================

        if score >= 75:

            threat_level = "CRITICAL"

        elif score >= 50:

            threat_level = "HIGH"

        elif score >= 25:

            threat_level = "MEDIUM"

        else:

            threat_level = "LOW"


        # ====================================================
        # CONFIDENCE
        # ====================================================

        if score >= 75:

            confidence = 0.90

        elif score >= 50:

            confidence = 0.80

        elif score >= 25:

            confidence = 0.70

        else:

            confidence = 0.60


        # ====================================================
        # FORECAST
        # ====================================================

        if score >= 75:

            predicted_stage = "Possible Attack Escalation"

            forecast_probability = min(
                95,
                score + 15
            )

            forecast_window = "1-5 minutes"


        elif score >= 50:

            predicted_stage = "Active Reconnaissance"

            forecast_probability = min(
                90,
                score + 10
            )

            forecast_window = "5-10 minutes"


        elif score >= 25:

            predicted_stage = "Early Reconnaissance"

            forecast_probability = min(
                80,
                score + 10
            )

            forecast_window = "10-20 minutes"


        else:

            predicted_stage = "Normal Network Behavior"

            forecast_probability = max(
                5,
                score
            )

            forecast_window = "20+ minutes"


        # ====================================================
        # FINAL RESULT
        # ====================================================

        return {

            "attack_type": attack_type,

            "risk_score": int(score),

            "threat_level": threat_level,

            "confidence": confidence,

            "features": features,

            "evidence": evidence,

            "forecast": {

                "probability":
                    int(forecast_probability),

                "predicted_stage":
                    predicted_stage,

                "forecast_window":
                    forecast_window
            }

        }


# ============================================================
# SINGLETON DETECTOR
# ============================================================

detector = NetGuardDetector()


# ============================================================
# HELPER FUNCTION
# ============================================================

def analyze_dataframe(dataframe):

    return detector.detect(
        dataframe
    )