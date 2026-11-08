import java.io.BufferedReader;
import java.io.StringReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class LogParser {

    public List<LogEntry> parseLogText(String content) {
        List<LogEntry> logs = new ArrayList<>();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        try (BufferedReader br = new BufferedReader(new StringReader(content))) {
            String line;

            while ((line = br.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");

                if (parts.length >= 5) {
                    String dateTime = parts[0] + " " + parts[1];
                    String eventType = parts[2];
                    String username = parts[3];
                    String ipAddress = parts[4];

                    logs.add(new LogEntry(
                            LocalDateTime.parse(dateTime, formatter),
                            eventType,
                            username,
                            ipAddress
                    ));
                }
            }
        } catch (Exception e) {
            System.out.println("Error parsing logs: " + e.getMessage());
        }

        return logs;
    }
}