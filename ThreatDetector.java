import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ThreatDetector {

    public List<ThreatAlert> detectThreats(List<LogEntry> logs) {
        List<ThreatAlert> alerts = new ArrayList<>();
        Map<String, Integer> failedLoginCount = new HashMap<>();

        for (LogEntry log : logs) {
            String ip = log.getIpAddress();
            String event = log.getEventType();
            String user = log.getUsername();
            int hour = log.getTimestamp().getHour();

            if (event.equals("LOGIN_FAILED")) {
                failedLoginCount.put(ip, failedLoginCount.getOrDefault(ip, 0) + 1);

                if (failedLoginCount.get(ip) >= 3) {
                    alerts.add(new ThreatAlert(
                            log,
                            "Brute Force Attempt",
                            "HIGH",
                            60,
                            "Multiple failed login attempts from IP " + ip
                    ));
                }
            }

            if (event.equals("LOGIN_SUCCESS") && hour >= 0 && hour <= 5) {
                alerts.add(new ThreatAlert(
                        log,
                        "Suspicious Login Time",
                        "MEDIUM",
                        40,
                        "Login at unusual time by user " + user
                ));
            }

            if (event.equals("ACCESS_DENIED")) {
                alerts.add(new ThreatAlert(
                        log,
                        "Unauthorized Access",
                        "MEDIUM",
                        30,
                        "Access denied event detected"
                ));
            }

            if (event.equals("FILE_DELETE") || event.equals("CONFIG_CHANGE")) {
                alerts.add(new ThreatAlert(
                        log,
                        "Sensitive Activity",
                        "CRITICAL",
                        80,
                        "Sensitive action detected: " + event
                ));
            }
        }

        return alerts;
    }
}