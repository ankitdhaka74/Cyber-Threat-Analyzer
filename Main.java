
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class Main {

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(
                new InetSocketAddress(8000), 0
        );

        server.createContext("/", exchange ->
                serveFile(exchange, "web/login.html",
                        "text/html; charset=UTF-8"));

        server.createContext("/login", exchange ->
                serveFile(exchange, "web/login.html",
                        "text/html; charset=UTF-8"));

        server.createContext("/signup", exchange ->
                serveFile(exchange, "web/signup.html",
                        "text/html; charset=UTF-8"));

        server.createContext("/dashboard", exchange ->
                serveFile(exchange, "web/index.html",
                        "text/html; charset=UTF-8"));

        server.createContext("/map", exchange ->
                serveFile(exchange, "web/map.html",
                        "text/html; charset=UTF-8"));

        server.createContext("/analyze", Main::handleAnalyze);

        server.setExecutor(null);
        server.start();

        System.out.println(
                "ThreatLens AI server started at http://localhost:8000"
        );
    }

    private static void serveFile(
            HttpExchange exchange,
            String path,
            String contentType
    ) throws IOException {

        try {
            byte[] response = Files.readAllBytes(Paths.get(path));

            exchange.getResponseHeaders().set(
                    "Content-Type", contentType
            );

            exchange.sendResponseHeaders(200, response.length);

            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }

        } catch (IOException e) {
            sendJson(exchange, 500,
                    "{\"error\":\"Could not load requested page.\"}");
        }
    }

    private static void handleAnalyze(
            HttpExchange exchange
    ) throws IOException {

        if (!"POST".equalsIgnoreCase(
                exchange.getRequestMethod())) {

            sendJson(exchange, 405,
                    "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        try {
            String requestBody = new String(
                    exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8
            );

            String logContent = extractFileContent(requestBody);

            if (logContent == null || logContent.isBlank()) {
                sendJson(exchange, 400,
                        "{\"error\":\"Could not read uploaded file.\"}");
                return;
            }

            LogParser parser = new LogParser();
            ThreatDetector detector = new ThreatDetector();

            List<LogEntry> logs = parser.parseLogText(logContent);
            List<ThreatAlert> alerts = detector.detectThreats(logs);

            String json = buildJson(logs, alerts);

            sendJson(exchange, 200, json);

        } catch (Exception e) {
            e.printStackTrace();

            sendJson(exchange, 500,
                    "{\"error\":\"Server error: "
                            + escape(e.getMessage() == null
                            ? "unknown" : e.getMessage())
                            + "\"}");
        }
    }

    private static String extractFileContent(String body) {
        int firstBlankLine = body.indexOf("\r\n\r\n");

        if (firstBlankLine == -1) {
            return null;
        }

        String afterHeaders = body.substring(firstBlankLine + 4);

        int endBoundary = afterHeaders.lastIndexOf("\r\n------");

        if (endBoundary == -1) {
            return afterHeaders.trim();
        }

        return afterHeaders.substring(0, endBoundary).trim();
    }

    private static String buildJson(
            List<LogEntry> logs,
            List<ThreatAlert> alerts
    ) {
        StringBuilder sb = new StringBuilder();

        DateTimeFormatter dateFormatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd");

        DateTimeFormatter timeFormatter =
                DateTimeFormatter.ofPattern("HH:mm:ss");

        sb.append("{");
        sb.append("\"totalLogs\":").append(logs.size()).append(",");
        sb.append("\"totalAlerts\":").append(alerts.size()).append(",");

        // Include all successful login events for travel analysis.
        sb.append("\"loginEvents\":[");

        boolean firstLogin = true;

        for (LogEntry log : logs) {
            if ("LOGIN_SUCCESS".equalsIgnoreCase(
                    log.getEventType())) {

                if (!firstLogin) {
                    sb.append(",");
                }

                firstLogin = false;

                sb.append("{");

                sb.append("\"date\":\"")
                        .append(escape(
                                log.getTimestamp().format(dateFormatter)))
                        .append("\",");

                sb.append("\"time\":\"")
                        .append(escape(
                                log.getTimestamp().format(timeFormatter)))
                        .append("\",");

                sb.append("\"username\":\"")
                        .append(escape(log.getUsername()))
                        .append("\",");

                sb.append("\"ipAddress\":\"")
                        .append(escape(log.getIpAddress()))
                        .append("\",");

                sb.append("\"eventType\":\"LOGIN_SUCCESS\"");

                sb.append("}");
            }
        }

        sb.append("],");

        // Existing threat alerts.
        sb.append("\"alerts\":[");

        for (int i = 0; i < alerts.size(); i++) {
            ThreatAlert alert = alerts.get(i);
            LogEntry log = alert.getLogEntry();

            if (i > 0) {
                sb.append(",");
            }

            sb.append("{");

            sb.append("\"date\":\"")
                    .append(escape(
                            log.getTimestamp().format(dateFormatter)))
                    .append("\",");

            sb.append("\"time\":\"")
                    .append(escape(
                            log.getTimestamp().format(timeFormatter)))
                    .append("\",");

            sb.append("\"username\":\"")
                    .append(escape(log.getUsername()))
                    .append("\",");

            sb.append("\"ipAddress\":\"")
                    .append(escape(log.getIpAddress()))
                    .append("\",");

            sb.append("\"eventType\":\"")
                    .append(escape(log.getEventType()))
                    .append("\",");

            sb.append("\"threatType\":\"")
                    .append(escape(alert.getThreatType()))
                    .append("\",");

            sb.append("\"severity\":\"")
                    .append(escape(alert.getSeverity()))
                    .append("\",");

            sb.append("\"riskScore\":")
                    .append(alert.getRiskScore())
                    .append(",");

            sb.append("\"message\":\"")
                    .append(escape(alert.getMessage()))
                    .append("\"");

            sb.append("}");
        }

        sb.append("]}");

        return sb.toString();
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }

        return text
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void sendJson(
            HttpExchange exchange,
            int status,
            String json
    ) throws IOException {

        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        Headers headers = exchange.getResponseHeaders();

        headers.set(
                "Content-Type",
                "application/json; charset=UTF-8"
        );

        exchange.sendResponseHeaders(status, bytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
