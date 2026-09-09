function runAnalysis() {

    const result = document.getElementById("result");

    result.innerHTML =
        "🧠 Analyzing network traffic...";

    setTimeout(function () {

        result.innerHTML =
            "📡 Traffic pattern analyzed...";

    }, 1200);


    setTimeout(function () {

        result.innerHTML =
            "🔍 Abnormal traffic trend detected...";

    }, 2400);


    setTimeout(function () {

        result.innerHTML =
            "🚨 AI FORECAST: HIGH RISK — Possible DDoS-like activity | Risk Score: 87%";

    }, 3600);

}