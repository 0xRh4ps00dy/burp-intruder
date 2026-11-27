package burp;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class RequestEngine {
    public static class PayloadInfo {
        final String value;
        final String source;
        public PayloadInfo(String value, String source) {
            this.value = value;
            this.source = source;
        }
    }

    private static class PayloadItem {
        final String[] payloads;
        final String source;
        PayloadItem(String[] payloads, String source) {
            this.payloads = payloads;
            this.source = source;
        }
    }

    private final String urlStr;

    private final byte[] template;
    private final List<List<PayloadInfo>> payloadSets;
    private final String attackMode;
    private final int threads;
    private final int reqPerConn;
    private final boolean pipeline;
    private final int delayMs;
    private final boolean encode;
    private final String encodeChars;
    private final Consumer<Map<String, Object>> callback;
    private final Runnable finishedCallback;
    private final List<String[]> payloadRules;
    private final boolean rawMode;
    private final int maxRetries;
    private final int retryDelayMs;

    private boolean running = false;
    private boolean paused = false;
    private final Object pauseLock = new Object();
    private int requestCount = 0;
    private final LinkedBlockingQueue<PayloadItem> queue = new LinkedBlockingQueue<>(1000);
    private int activeThreads = 0;


    private static class RequestDestination {
        final String host;
        final int port;
        final boolean https;

        RequestDestination(String host, int port, boolean https) {
            this.host = host;
            this.port = port;
            this.https = https;
        }
    }

    private static SSLSocketFactory sslSocketFactory;

    static {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            sslSocketFactory = sc.getSocketFactory();
        } catch (Exception e) {
            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
    }

    public RequestEngine(String url, byte[] template, List<List<PayloadInfo>> payloadSets, String attackMode, int threads, int reqPerConn, boolean pipeline, int delayMs, boolean encode, String encodeChars, Consumer<Map<String, Object>> callback, Runnable finishedCallback, List<String[]> payloadRules, boolean rawMode, int maxRetries, int retryDelayMs) {

        this.urlStr = url;
        this.rawMode = rawMode;
        this.template = rawMode ? template : normalizeTemplate(template);
        this.payloadSets = payloadSets;
        this.attackMode = attackMode;
        this.threads = threads;
        this.reqPerConn = reqPerConn;
        this.pipeline = pipeline;
        this.delayMs = delayMs;
        this.encode = encode;
        this.encodeChars = encodeChars;
        this.callback = callback;
        this.finishedCallback = finishedCallback;
        this.payloadRules = payloadRules;
        this.maxRetries = maxRetries;
        this.retryDelayMs = retryDelayMs;
    }

    private byte[] normalizeTemplate(byte[] template) {
        try {
            String req = new String(template, StandardCharsets.ISO_8859_1);
            // Only normalize if it's explicitly HTTP/2 text representation from Burp
            if (req.contains("HTTP/2")) {
                int headerEnd = req.indexOf("\r\n\r\n");
                if (headerEnd == -1) headerEnd = req.indexOf("\n\n");
                
                if (headerEnd == -1) return template;

                String headerSection = req.substring(0, headerEnd);
                String body = req.substring(headerEnd); // Keep the separator and body

                // Replace version and remove pseudo-headers while preserving other lines
                headerSection = headerSection.replaceFirst("HTTP/2", "HTTP/1.1");
                String[] lines = headerSection.split("\\r?\\n");
                StringBuilder sb = new StringBuilder();
                boolean hostPresent = false;
                for (String line : lines) {
                    if (line.toLowerCase().startsWith("host:")) hostPresent = true;
                }

                for (String line : lines) {
                    String trimmed = line.trim();
                    if (trimmed.toLowerCase().startsWith(":authority:")) {
                        if (!hostPresent) {
                            if (sb.length() > 0) sb.append("\r\n");
                            sb.append("Host: ").append(trimmed.substring(11).trim());
                            hostPresent = true;
                        }
                        continue;
                    }
                    if (trimmed.startsWith(":") || trimmed.isEmpty()) continue;
                    if (sb.length() > 0) sb.append("\r\n");
                    sb.append(line);
                }



                // If body only contains newlines, trim them to avoid extra space
                if (body.trim().isEmpty() && body.length() > 4) {
                    body = "\r\n\r\n";
                }

                return (sb.toString() + body).getBytes(StandardCharsets.ISO_8859_1);
            }
        } catch (Exception ignored) {}
        return template;
    }

    public boolean isRunning() {
        return running;
    }

    public void start() {
        this.running = true;


        new Thread(this::producer).start();
        for (int i = 0; i < threads; i++) {
            activeThreads++;
            new Thread(this::worker).start();
        }
    }

    public void stop() {
        this.running = false;
        resume(); // Ensure threads aren't stuck in checkPaused
        queue.clear();
    }

    public void pause() {
        synchronized (pauseLock) {
            paused = true;
        }
    }

    public void resume() {
        synchronized (pauseLock) {
            paused = false;
            pauseLock.notifyAll();
        }
    }

    private void checkPaused() throws InterruptedException {
        synchronized (pauseLock) {
            while (paused && running) {
                pauseLock.wait();
            }
        }
    }

    private void producer() {
        try {
            if (attackMode.equals("Cluster Bomb")) {
                generateCartesianProduct(payloadSets, 0, new String[payloadSets.size()], new StringBuilder());
            } else if (attackMode.equals("Sniper")) {
                int totalMarkers = countMarkers(urlStr) + countMarkers(new String(template, StandardCharsets.ISO_8859_1));
                int pairs = totalMarkers / 2;
                List<PayloadInfo> words = payloadSets.get(0);
                for (int i = 0; i < pairs && running; i++) {
                    for (PayloadInfo info : words) {
                        if (!running) break;
                        String[] payload = new String[pairs];
                        java.util.Arrays.fill(payload, null);
                        payload[i] = info.value;
                        queue.put(new PayloadItem(payload, info.source));
                    }
                }
            } else { // Battering Ram
                List<PayloadInfo> words = payloadSets.get(0);
                int totalMarkers = countMarkers(urlStr) + countMarkers(new String(template, StandardCharsets.ISO_8859_1));
                int pairs = totalMarkers / 2;
                for (PayloadInfo info : words) {
                    if (!running) break;
                    String[] payload = new String[pairs];
                    java.util.Arrays.fill(payload, info.value);
                    queue.put(new PayloadItem(payload, info.source));
                }
            }
            
            for (int i = 0; i < threads; i++) queue.put(new PayloadItem(new String[]{"POISON_PILL"}, ""));

        } catch (Exception ignored) {}
    }

    private void generateCartesianProduct(List<List<PayloadInfo>> sets, int depth, String[] current, StringBuilder source) throws InterruptedException {
        if (!running) return;
        if (depth == sets.size()) {
            queue.put(new PayloadItem(current.clone(), source.toString()));
            return;
        }
        int sourceLen = source.length();
        for (PayloadInfo info : sets.get(depth)) {
            current[depth] = info.value;
            if (sourceLen > 0) source.append(", ");
            source.append(info.source);
            generateCartesianProduct(sets, depth + 1, current, source);
            source.setLength(sourceLen);
            if (!running) break;
        }
    }


    private int countMarkers(String text) {
        int count = 0;
        for (char c : text.toCharArray()) if (c == '§') count++;
        return count;
    }

    private void worker() {
        try {
            Socket socket = null;
            int sentOnConn = 0;
            String connHost = null;
            int connPort = -1;
            boolean connHttps = false;

            while (running) {
                checkPaused();
                PayloadItem item = queue.take();
                String[] payloads = item.payloads;
                if (payloads.length > 0 && payloads[0].equals("POISON_PILL")) break;

                byte[] request = buildRequest(payloads);

                long startT = System.currentTimeMillis();
                int attempts = 0;

                while (attempts < (maxRetries + 1) && running) {
                    attempts++;
                    try {
                        RequestDestination destination = resolveDestination(payloads, request);
                        String host = destination.host;
                        int port = destination.port;
                        boolean isHttps = destination.https;

                        boolean destinationChanged = connHost == null
                                || !connHost.equalsIgnoreCase(host)
                                || connPort != port
                                || connHttps != isHttps;

                        if (socket == null || sentOnConn >= reqPerConn || destinationChanged) {
                            if (socket != null) {
                                try { socket.close(); } catch (Exception ignored) {}
                            }
                            Socket plainSocket = new Socket();
                            plainSocket.connect(new java.net.InetSocketAddress(host, port), 3000); // 3s connection timeout
                            socket = isHttps ? sslSocketFactory.createSocket(plainSocket, host, port, true) : plainSocket;
                            socket.setSoTimeout(3000); // 3s read timeout
                            sentOnConn = 0;
                            connHost = host;
                            connPort = port;
                            connHttps = isHttps;
                        }

                        OutputStream out = socket.getOutputStream();
                        out.write(request);
                        out.flush();

                        InputStream in = socket.getInputStream();
                        ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
                        
                        byte[] buffer = new byte[8192];
                        int n;
                        String headers = "";
                        int headerEndIdx = -1;

                        // Read headers
                        while ((n = in.read(buffer)) != -1) {
                            responseBuffer.write(buffer, 0, n);
                            headers = responseBuffer.toString("ISO-8859-1");
                            headerEndIdx = headers.indexOf("\r\n\r\n");
                            if (headerEndIdx != -1) break;
                            if (headers.length() > 65536) break; // Safety break
                        }

                        if (headerEndIdx == -1) {
                            throw new IOException("Connection closed or response malformed while reading headers");
                        }

                        // Parse Content-Length if present
                        int cl = -1;
                        Pattern p = Pattern.compile("Content-Length:\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
                        Matcher m = p.matcher(headers);
                        if (m.find()) cl = Integer.parseInt(m.group(1));

                        boolean isChunked = headers.toLowerCase().contains("transfer-encoding: chunked");
                        
                        if (isChunked) {
                            while (running) {
                                String currentStr = responseBuffer.toString("ISO-8859-1");
                                if (currentStr.endsWith("0\r\n\r\n")) break;
                                n = in.read(buffer);
                                if (n == -1) break;
                                responseBuffer.write(buffer, 0, n);
                            }
                        } else if (cl >= 0) {
                            int bodyRead = responseBuffer.size() - (headerEndIdx + 4);
                            while (bodyRead < cl && running) {
                                n = in.read(buffer, 0, Math.min(buffer.length, cl - bodyRead));
                                if (n == -1) break;
                                responseBuffer.write(buffer, 0, n);
                                bodyRead += n;
                            }
                        }

                        byte[] fullResponse = responseBuffer.toByteArray();
                        fullResponse = decodeHttpResponseIfNeeded(fullResponse);
                        int status = 0;
                        String firstLine = headers.split("\r\n")[0];
                        if (firstLine.contains(" ")) {
                            String[] parts = firstLine.split(" ");
                            if (parts.length > 1) {
                                try { status = Integer.parseInt(parts[1]); } catch (Exception ignored) {}
                            }
                        }

                        Map<String, Object> res = new HashMap<>();
                        res.put("id", ++requestCount);
                        res.put("payload", String.join(", ", payloads));
                        res.put("payloads", payloads.clone());
                        res.put("status", status);
                        res.put("length", fullResponse.length);
                        res.put("time", (int) (System.currentTimeMillis() - startT));
                        res.put("request", request);
                        res.put("response", fullResponse);
                        res.put("wordlist", item.source);
                        callback.accept(res);


                        sentOnConn++;
                        if (delayMs > 0) {
                            Thread.sleep(delayMs);
                        }
                        break; // Success, exit attempt loop

                    } catch (Exception e) {
                        try {
                            if (socket != null) socket.close();
                        } catch (Exception ignored) {}
                        socket = null;
                        connHost = null;
                        connPort = -1;
                        connHttps = false;

                        boolean isConnError = (e instanceof IOException || e instanceof java.net.SocketException)
                                              && !(e instanceof java.net.UnknownHostException);
                        
                        if (attempts < (maxRetries + 1) && isConnError && running) {
                            if (retryDelayMs > 0) {
                                try { Thread.sleep(retryDelayMs); } catch (InterruptedException ignored) {}
                            }
                            // Silently retry
                            continue;
                        }

                        // Report error if we give up or it's not a retryable error
                        Map<String, Object> res = new HashMap<>();
                        res.put("id", ++requestCount);
                        res.put("payload", String.join(", ", payloads));
                        res.put("payloads", payloads.clone());
                        res.put("status", 0);
                        res.put("length", 0);
                        res.put("time", (int) (System.currentTimeMillis() - startT));
                        res.put("request", request);
                        res.put("response", new byte[0]);
                        String err = e.getClass().getSimpleName();
                        if (e.getMessage() != null && !e.getMessage().isEmpty()) {
                            err += ": " + e.getMessage();
                        }
                        res.put("error", err);
                        res.put("wordlist", item.source);
                        callback.accept(res);

                        break;
                    }
                }
            }
            if (socket != null) socket.close();
        } catch (Exception ignored) {} finally {
            activeThreads--;
            if (activeThreads == 0) finishedCallback.run();
        }
    }

    private String buildUrl(String[] payloads) {
        return replaceMarkersPositional(urlStr, payloads, 0);
    }

    private RequestDestination resolveDestination(String[] payloads, byte[] requestBytes) {
        try {
            URL fallback = new URL(buildUrl(payloads));
            String fallbackHost = fallback.getHost();
            boolean fallbackHttps = fallback.getProtocol().equalsIgnoreCase("https");
            int fallbackPort = fallback.getPort() != -1 ? fallback.getPort() : fallback.getDefaultPort();

            String request = new String(requestBytes, StandardCharsets.ISO_8859_1);
            int headerEnd = request.indexOf("\r\n\r\n");
            String headers = headerEnd >= 0 ? request.substring(0, headerEnd) : request;
            String[] lines = headers.split("\r\n");

            if (lines.length > 0) {
                String[] reqParts = lines[0].split(" ");
                if (reqParts.length >= 2) {
                    String target = reqParts[1].trim();
                    if (target.startsWith("http://") || target.startsWith("https://")) {
                        URL absolute = new URL(target);
                        boolean https = absolute.getProtocol().equalsIgnoreCase("https");
                        int port = absolute.getPort() != -1 ? absolute.getPort() : absolute.getDefaultPort();
                        return new RequestDestination(absolute.getHost(), port, https);
                    }
                }
            }

            Pattern hostPattern = Pattern.compile("(?im)^Host:\\s*([^\\r\\n]+)");
            Matcher hostMatcher = hostPattern.matcher(headers);
            if (hostMatcher.find()) {
                String hostHeader = hostMatcher.group(1).trim();
                String host = hostHeader;
                int port = fallbackPort;

                if (host.startsWith("[")) {
                    int closingBracket = host.indexOf(']');
                    if (closingBracket > 0) {
                        String ipv6Host = host.substring(0, closingBracket + 1);
                        String rest = host.substring(closingBracket + 1);
                        host = ipv6Host;
                        if (rest.startsWith(":")) {
                            try {
                                port = Integer.parseInt(rest.substring(1));
                            } catch (NumberFormatException ignored) {}
                        }
                    }
                } else {
                    int lastColon = host.lastIndexOf(':');
                    if (lastColon > 0 && host.indexOf(':') == lastColon) {
                        try {
                            port = Integer.parseInt(host.substring(lastColon + 1));
                            host = host.substring(0, lastColon);
                        } catch (NumberFormatException ignored) {
                            host = hostHeader;
                        }
                    }
                }

                if (!host.isEmpty()) {
                    return new RequestDestination(host, port, fallbackHttps);
                }
            }

            return new RequestDestination(fallbackHost, fallbackPort, fallbackHttps);
        } catch (Exception ignored) {
            return fallbackFromTarget();
        }
    }

    private RequestDestination fallbackFromTarget() {
        String cleaned = urlStr == null ? "" : urlStr.replace("\u00a7", "");
        try {
            URL fallback = new URL(cleaned);
            boolean https = fallback.getProtocol().equalsIgnoreCase("https");
            int port = fallback.getPort() != -1 ? fallback.getPort() : fallback.getDefaultPort();
            return new RequestDestination(fallback.getHost(), port, https);
        } catch (Exception ignored) {
            boolean https = cleaned.toLowerCase().startsWith("https://");
            return new RequestDestination("127.0.0.1", https ? 443 : 80, https);
        }
    }

    private byte[] decodeHttpResponseIfNeeded(byte[] responseBytes) {
        try {
            int headerEnd = findHeaderEnd(responseBytes);
            if (headerEnd < 0) {
                return responseBytes;
            }

            String headerText = new String(responseBytes, 0, headerEnd, StandardCharsets.ISO_8859_1);
            byte[] body = new byte[Math.max(0, responseBytes.length - headerEnd - 4)];
            if (body.length > 0) {
                System.arraycopy(responseBytes, headerEnd + 4, body, 0, body.length);
            }

            boolean hasChunked = hasHeaderToken(headerText, "Transfer-Encoding", "chunked");
            if (hasChunked) {
                body = decodeChunkedBody(body);
            }

            String contentEncodingHeader = getHeaderValue(headerText, "Content-Encoding");
            if (contentEncodingHeader != null && !contentEncodingHeader.trim().isEmpty()) {
                body = decodeContentEncoding(body, contentEncodingHeader);
            }

            String rebuiltHeaders = rebuildHeadersAfterDecoding(headerText, body.length);
            byte[] headerBytes = rebuiltHeaders.getBytes(StandardCharsets.ISO_8859_1);
            ByteArrayOutputStream out = new ByteArrayOutputStream(headerBytes.length + 4 + body.length);
            out.write(headerBytes);
            out.write('\r');
            out.write('\n');
            out.write('\r');
            out.write('\n');
            out.write(body);
            return out.toByteArray();
        } catch (Exception ignored) {
            return responseBytes;
        }
    }

    private int findHeaderEnd(byte[] responseBytes) {
        for (int i = 0; i + 3 < responseBytes.length; i++) {
            if (responseBytes[i] == '\r'
                    && responseBytes[i + 1] == '\n'
                    && responseBytes[i + 2] == '\r'
                    && responseBytes[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private String getHeaderValue(String headerText, String headerName) {
        Pattern p = Pattern.compile("(?im)^" + Pattern.quote(headerName) + "\\s*:\\s*([^\\r\\n]+)");
        Matcher m = p.matcher(headerText);
        return m.find() ? m.group(1).trim() : null;
    }

    private boolean hasHeaderToken(String headerText, String headerName, String token) {
        String value = getHeaderValue(headerText, headerName);
        if (value == null) {
            return false;
        }
        for (String part : value.split(",")) {
            if (token.equalsIgnoreCase(part.trim())) {
                return true;
            }
        }
        return false;
    }

    private byte[] decodeChunkedBody(byte[] chunkedBody) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(chunkedBody);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        while (true) {
            String sizeLine = readAsciiLine(in);
            if (sizeLine == null) {
                break;
            }
            int semicolon = sizeLine.indexOf(';');
            String sizeToken = (semicolon >= 0 ? sizeLine.substring(0, semicolon) : sizeLine).trim();
            if (sizeToken.isEmpty()) {
                continue;
            }

            int chunkSize = Integer.parseInt(sizeToken, 16);
            if (chunkSize == 0) {
                // Consume optional trailers.
                while (true) {
                    String trailer = readAsciiLine(in);
                    if (trailer == null || trailer.isEmpty()) {
                        break;
                    }
                }
                break;
            }

            byte[] chunk = new byte[chunkSize];
            int read = 0;
            while (read < chunkSize) {
                int count = in.read(chunk, read, chunkSize - read);
                if (count == -1) break;
                read += count;
            }
            if (read < chunkSize) {
                throw new EOFException("Unexpected end of chunked body");
            }
            out.write(chunk, 0, read);

            int cr = in.read();
            int lf = in.read();
            if (cr != '\r' || lf != '\n') {
                throw new IOException("Invalid chunk delimiter");
            }
        }

        return out.toByteArray();
    }

    private String readAsciiLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        boolean sawAny = false;
        while ((b = in.read()) != -1) {
            sawAny = true;
            if (b == '\r') {
                int next = in.read();
                if (next == '\n') {
                    return line.toString(StandardCharsets.ISO_8859_1.name());
                }
                if (next != -1) {
                    line.write(next);
                }
                line.write(b);
                continue;
            }
            line.write(b);
        }
        if (!sawAny && line.size() == 0) {
            return null;
        }
        return line.toString(StandardCharsets.ISO_8859_1.name());
    }

    private byte[] decodeContentEncoding(byte[] body, String contentEncodingHeader) throws IOException {
        String[] encodings = contentEncodingHeader.split(",");
        byte[] decoded = body;

        for (int i = encodings.length - 1; i >= 0; i--) {
            String encoding = encodings[i].trim().toLowerCase();
            if (encoding.isEmpty() || "identity".equals(encoding)) {
                continue;
            }
            if ("gzip".equals(encoding) || "x-gzip".equals(encoding)) {
                decoded = readAll(new GZIPInputStream(new ByteArrayInputStream(decoded)));
            } else if ("deflate".equals(encoding)) {
                try {
                    decoded = readAll(new InflaterInputStream(new ByteArrayInputStream(decoded), new Inflater(false)));
                } catch (Exception first) {
                    decoded = readAll(new InflaterInputStream(new ByteArrayInputStream(decoded), new Inflater(true)));
                }
            } else if ("br".equals(encoding)) {
                decoded = decodeBrotli(decoded);
            }
        }

        return decoded;
    }

    private byte[] decodeBrotli(byte[] body) throws IOException {
        try {
            Class<?> cls = Class.forName("org.brotli.dec.BrotliInputStream");
            InputStream brotli = (InputStream) cls.getConstructor(InputStream.class)
                    .newInstance(new ByteArrayInputStream(body));
            return readAll(brotli);
        } catch (ClassNotFoundException e) {
            throw new IOException("Brotli decoder not present", e);
        } catch (ReflectiveOperationException e) {
            throw new IOException("Failed to decode Brotli body", e);
        }
    }

    private byte[] readAll(InputStream in) throws IOException {
        try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = input.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private String rebuildHeadersAfterDecoding(String headerText, int newBodyLength) {
        String[] lines = headerText.split("\\r\\n");
        StringBuilder rebuilt = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i == 0) {
                rebuilt.append(line);
                continue;
            }

            String lower = line.toLowerCase();
            if (lower.startsWith("transfer-encoding:")) {
                continue;
            }
            if (lower.startsWith("content-encoding:")) {
                continue;
            }
            if (lower.startsWith("content-length:")) {
                continue;
            }
            rebuilt.append("\r\n").append(line);
        }

        rebuilt.append("\r\nContent-Length: ").append(newBodyLength);
        return rebuilt.toString();
    }

    private byte[] buildRequest(String[] payloads) {
        int markersInUrl = countMarkers(urlStr) / 2;
        String reqStr = replaceMarkersPositional(new String(template, StandardCharsets.ISO_8859_1), payloads, markersInUrl);
        if (!rawMode) {
            reqStr = syncRequestWithTarget(reqStr, buildUrl(payloads));
        }
        reqStr = enforceIdentityAcceptEncoding(reqStr);
        return reqStr.getBytes(StandardCharsets.ISO_8859_1);
    }

    private String enforceIdentityAcceptEncoding(String request) {
        try {
            int headerEnd = request.indexOf("\r\n\r\n");
            String separator = "\r\n\r\n";
            if (headerEnd < 0) {
                headerEnd = request.indexOf("\n\n");
                separator = "\n\n";
            }

            String headerSection = headerEnd >= 0 ? request.substring(0, headerEnd) : request;
            String body = headerEnd >= 0 ? request.substring(headerEnd + separator.length()) : "";

            String[] lines = headerSection.split("\\r?\\n");
            if (lines.length == 0) return request;

            boolean found = false;
            for (int i = 1; i < lines.length; i++) {
                if (lines[i].toLowerCase().startsWith("accept-encoding:")) {
                    int colon = lines[i].indexOf(':');
                    String prefix = colon >= 0 ? lines[i].substring(0, colon + 1) : "Accept-Encoding:";
                    lines[i] = prefix + " identity";
                    found = true;
                    break;
                }
            }

            if (!found) {
                String[] expanded = new String[lines.length + 1];
                expanded[0] = lines[0];
                expanded[1] = "Accept-Encoding: identity";
                System.arraycopy(lines, 1, expanded, 2, lines.length - 1);
                lines = expanded;
            }

            String newHeader = String.join("\r\n", lines);
            if (headerEnd < 0) {
                return newHeader;
            }
            if (body.isEmpty()) {
                return newHeader + "\r\n\r\n";
            }
            return newHeader + "\r\n\r\n" + body;
        } catch (Exception ignored) {
            return request;
        }
    }

    private String syncRequestWithTarget(String request, String targetUrl) {
        try {
            String[] targetParts = extractTargetSchemeAndAuthority(targetUrl);
            if (targetParts == null) return request;
            String protocol = targetParts[0];
            String authority = targetParts[1];

            // Use a more surgical approach to preserve original formatting
            int headerEnd = request.indexOf("\r\n\r\n");
            String separator = "\r\n\r\n";
            if (headerEnd < 0) {
                headerEnd = request.indexOf("\n\n");
                separator = "\n\n";
            }

            String headerSection = headerEnd >= 0 ? request.substring(0, headerEnd) : request;
            String body = headerEnd >= 0 ? request.substring(headerEnd + separator.length()) : "";

            String[] lines = headerSection.split("\\r?\\n");
            if (lines.length == 0) return request;

            // 1. Sync Request Line (only if it matches target partially or needs update)
            String[] firstLineParts = lines[0].split(" ", 3);
            if (firstLineParts.length >= 3) {
                String method = firstLineParts[0];
                String requestTarget = firstLineParts[1];
                String version = firstLineParts[2];

                if ("CONNECT".equalsIgnoreCase(method)) {
                    lines[0] = method + " " + authority + " " + version;
                } else if (requestTarget.startsWith("http://") || requestTarget.startsWith("https://")) {
                    String pathAndQuery = "/";
                    try {
                        URL current = new URL(requestTarget);
                        String file = current.getFile();
                        if (file != null && !file.isEmpty()) pathAndQuery = file;
                    } catch (Exception ignored) {
                        int pathStart = requestTarget.indexOf('/', requestTarget.indexOf("://") + 3);
                        if (pathStart >= 0) pathAndQuery = requestTarget.substring(pathStart);
                    }
                    lines[0] = method + " " + protocol + "://" + authority + pathAndQuery + " " + version;
                }
            }

            // 2. Sync Host Header (only change value, preserve casing and spacing if possible)
            boolean hostHeaderFound = false;
            // Clean authority for Host header (remove default ports)
            String hostValue = authority;
            if (protocol.equalsIgnoreCase("https") && authority.endsWith(":443")) {
                hostValue = authority.substring(0, authority.length() - 4);
            } else if (protocol.equalsIgnoreCase("http") && authority.endsWith(":80")) {
                hostValue = authority.substring(0, authority.length() - 3);
            }

            for (int i = 1; i < lines.length; i++) {
                if (lines[i].toLowerCase().startsWith("host:")) {
                    int colonIdx = lines[i].indexOf(':');
                    String prefix = lines[i].substring(0, colonIdx + 1);
                    // Preserve the spacing after the colon if it exists
                    String spacing = "";
                    if (lines[i].length() > colonIdx + 1 && lines[i].charAt(colonIdx + 1) == ' ') {
                        spacing = " ";
                    }
                    lines[i] = prefix + spacing + hostValue;
                    hostHeaderFound = true;
                    break;
                }
            }

            if (!hostHeaderFound) {
                String[] expanded = new String[lines.length + 1];
                expanded[0] = lines[0];
                expanded[1] = "Host: " + hostValue;
                System.arraycopy(lines, 1, expanded, 2, lines.length - 1);
                lines = expanded;
            }

            String newHeader = String.join("\r\n", lines);
            // Ensure we don't add extra newlines if body is empty
            if (body.isEmpty()) {
                return newHeader + "\r\n\r\n";
            }
            return newHeader + "\r\n\r\n" + body;
        } catch (Exception ignored) {
            return request;
        }
    }

    private String[] extractTargetSchemeAndAuthority(String targetUrl) {
        if (targetUrl == null) return null;

        Pattern p = Pattern.compile("(?i)^([a-z][a-z0-9+.-]*)://([^/\\s]+)");
        Matcher m = p.matcher(targetUrl.trim());
        if (!m.find()) return null;

        String scheme = m.group(1).toLowerCase();
        String authority = m.group(2).trim();
        if (authority.isEmpty()) return null;

        // Add default port if target authority did not include one.
        if (!hasExplicitPort(authority)) {
            int defaultPort = "https".equals(scheme) ? 443 : 80;
            authority = authority + ":" + defaultPort;
        }

        return new String[]{scheme, authority};
    }

    private boolean hasExplicitPort(String authority) {
        if (authority.startsWith("[")) {
            int closing = authority.indexOf(']');
            return closing >= 0 && closing + 1 < authority.length() && authority.charAt(closing + 1) == ':';
        }
        int idx = authority.lastIndexOf(':');
        return idx > 0 && authority.indexOf(':') == idx;
    }

    private String replaceMarkersPositional(String text, String[] payloads, int startOffset) {
        StringBuilder sb = new StringBuilder();
        int payloadIdx = startOffset;
        int lastPos = 0;
        int firstMarker = text.indexOf('§');
        
        while (firstMarker != -1) {
            int secondMarker = text.indexOf('§', firstMarker + 1);
            if (secondMarker == -1) break;
            
            sb.append(text, lastPos, firstMarker);
            String markerDefault = text.substring(firstMarker + 1, secondMarker);
            String payloadWord = (payloadIdx < payloads.length) ? payloads[payloadIdx] : null;

            if (payloadWord == null) {
                // If this position is not targeted in current attack mode, keep original marker content.
                sb.append(markerDefault);
            } else {
                String processed = payloadWord;
                if (payloadRules != null) {
                    for (String[] rule : payloadRules) {
                        processed = applyRule(processed, rule[0], rule[1]);
                    }
                }
                if (encode && encodeChars != null && !encodeChars.isEmpty()) {
                    StringBuilder esb = new StringBuilder();
                    for (char c : processed.toCharArray()) {
                        if (encodeChars.indexOf(c) != -1) esb.append(String.format("%%%02X", (int) c));
                        else esb.append(c);
                    }
                    processed = esb.toString();
                }

                sb.append(processed);
            }

            lastPos = secondMarker + 1;
            payloadIdx++;
            firstMarker = text.indexOf('§', lastPos);
        }
        sb.append(text.substring(lastPos));
        return sb.toString();
    }

    private String applyRule(String input, String type, String arg) {
        try {
            switch (type) {
                case "MD5": return hash(input, "MD5");
                case "SHA-1": return hash(input, "SHA-1");
                case "SHA-256": return hash(input, "SHA-256");
                case "Base64 Encode": return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
                case "Hex Encode": 
                    StringBuilder hex = new StringBuilder();
                    for (byte b : input.getBytes(StandardCharsets.UTF_8)) hex.append(String.format("%02x", b));
                    return hex.toString();
                case "Add Prefix": return arg + input;
                case "Add Suffix": return input + arg;
                case "Upper Case": return input.toUpperCase();
                case "Lower Case": return input.toLowerCase();
                default: return input;
            }
        } catch (Exception e) { return input; }
    }

    private String hash(String input, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
