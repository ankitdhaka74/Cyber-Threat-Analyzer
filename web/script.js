document.getElementById("analyzeBtn").addEventListener("click", analyzeLogFile);

function analyzeLogFile() {
  const fileInput = document.getElementById("fileInput");
  const errorBox = document.getElementById("errorBox");
  const resultTable = document.getElementById("resultTable");
  const tbody = resultTable.querySelector("tbody");
  const summary = document.getElementById("summary");

  errorBox.style.display = "none";
  resultTable.style.display = "none";
  summary.style.display = "none";
  tbody.innerHTML = "";

  const file = fileInput.files[0];

  if (!file) {
    showError("Please select a log file first.");
    return;
  }

  const reader = new FileReader();

  reader.onload = function (event) {
    try {
      const content = event.target.result;
      const lines = content.split(/\r?\n/).filter(line => line.trim() !== "");

      const failedLoginByIp = {};
      const alerts = [];

      for (const line of lines) {
        const parts = line.trim().split(/\s+/);

        if (parts.length < 5) continue;

        const timestamp = parts[0] + " " + parts[1];
        const eventType = parts[2];
        const username = parts[3];
        const ipAddress = parts[4];

        let threatType = "Normal Activity";
        let severity = "LOW";
        let riskScore = 0;
        let message = "No suspicious activity detected";

        if (eventType === "LOGIN_FAILED") {
          failedLoginByIp[ipAddress] = (failedLoginByIp[ipAddress] || 0) + 1;
          if (failedLoginByIp[ipAddress] >= 3) {
            threatType = "Brute Force Attempt";
            severity = "HIGH";
            riskScore = 60;
            message = `Multiple failed login attempts from IP ${ipAddress}`;
          }
        }

        const hour = parseInt(parts[1].split(":")[0], 10);
        if (eventType === "LOGIN_SUCCESS" && hour >= 0 && hour <= 5) {
          threatType = "Suspicious Login Time";
          severity = "MEDIUM";
          riskScore = 40;
          message = `Login at unusual time by user ${username}`;
        }

        if (eventType === "ACCESS_DENIED") {
          threatType = "Unauthorized Access";
          severity = "MEDIUM";
          riskScore = 30;
          message = "Access denied event detected";
        }

        if (eventType === "FILE_DELETE" || eventType === "CONFIG_CHANGE") {
          threatType = "Sensitive Activity";
          severity = "CRITICAL";
          riskScore = 80;
          message = `Sensitive action detected: ${eventType}`;
        }

        if (threatType !== "Normal Activity") {
          alerts.push({
            timestamp,
            username,
            ipAddress,
            eventType,
            threatType,
            severity,
            riskScore,
            message
          });
        }
      }

      document.getElementById("totalLogs").textContent = lines.length;
      document.getElementById("totalThreats").textContent = alerts.length;
      document.getElementById("criticalThreats").textContent =
        alerts.filter(a => a.severity === "CRITICAL").length;

      for (const alert of alerts) {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${alert.timestamp}</td>
          <td>${alert.username}</td>
          <td>${alert.ipAddress}</td>
          <td>${alert.eventType}</td>
          <td>${alert.threatType}</td>
          <td>${alert.severity}</td>
          <td>${alert.riskScore}</td>
          <td>${alert.message}</td>
        `;
        tbody.appendChild(row);
      }

      summary.style.display = "flex";
      resultTable.style.display = "table";

      if (alerts.length === 0) {
        showError("No suspicious activity found in this log file.");
      }
    } catch (error) {
      showError("Error analyzing file.");
      console.error(error);
    }
  };

  reader.readAsText(file);
}

function showError(message) {
  const errorBox = document.getElementById("errorBox");
  errorBox.textContent = message;
  errorBox.style.display = "block";
}