import java.time.LocalDateTime;

public class LogEntry {
    private LocalDateTime timestamp;
    private String eventType;
    private String username;
    private String ipAddress;

    public LogEntry(LocalDateTime timestamp, String eventType, String username, String ipAddress) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.username = username;
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getUsername() {
        return username;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}