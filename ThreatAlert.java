public class ThreatAlert {
    private LogEntry logEntry;
    private String threatType;
    private String severity;
    private int riskScore;
    private String message;

    public ThreatAlert(LogEntry logEntry, String threatType, String severity, int riskScore, String message) {
        this.logEntry = logEntry;
        this.threatType = threatType;
        this.severity = severity;
        this.riskScore = riskScore;
        this.message = message;
    }

    public LogEntry getLogEntry() {
        return logEntry;
    }

    public String getThreatType() {
        return threatType;
    }

    public String getSeverity() {
        return severity;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getMessage() {
        return message;
    }
}