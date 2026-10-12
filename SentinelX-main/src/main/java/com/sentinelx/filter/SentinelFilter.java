package com.sentinelx.filter;

import com.sentinelx.service.ActionService;
import com.sentinelx.service.DetectionService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@Component
@Order(1)
public class SentinelFilter implements Filter {

    private static final Logger log = Logger.getLogger(SentinelFilter.class.getName());

    private final ActionService actionService;
    private final DetectionService detectionService;

    public SentinelFilter(ActionService actionService, DetectionService detectionService) {
        this.actionService = actionService;
        this.detectionService = detectionService;
    }

    // ── Attack patterns ───────────────────────────────────────
    private static final Pattern SQL_PATTERN = Pattern.compile(
        "(?i)(union.*select|select.*from|insert.*into|drop.*table|" +
        "delete.*from|update.*set|exec\\s*\\(|xp_cmdshell|" +
        "or\\s+1\\s*=\\s*1|and\\s+1\\s*=\\s*1|'\\s*or\\s*'|" +
        "1\\s*=\\s*1|admin'|'\\s*--)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script[^>]*>|</script>|javascript:|vbscript:|" +
        "onerror\\s*=|onload\\s*=|onclick\\s*=|eval\\s*\\(|" +
        "document\\.cookie|window\\.location|<iframe|alert\\s*\\()",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
        "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.%2e/|%252e%252e)",
        Pattern.CASE_INSENSITIVE
    );

    private static final String[] BAD_USER_AGENTS = {
        "sqlmap", "nikto", "masscan", "nmap", "dirbuster",
        "hydra", "burpsuite", "acunetix", "nessus", "openvas"
    };

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request  = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String ip        = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String uri       = request.getRequestURI();

        // ── Check 1: Blocked IP ───────────────────────────────
        if (actionService.isBlocked(ip)) {
            log.warning("[SENTINEL] Blocked IP attempted access: " + ip);
            response.sendError(403, "Your IP has been blocked by SentinelX.");
            return;
        }

        // ── Check 2: Known scanner user-agent ─────────────────
        if (userAgent != null && isKnownScanner(userAgent.toLowerCase())) {
            log.warning("[SENTINEL] Scanner detected from " + ip + ": " + userAgent);
            actionService.blockIp(ip, "SCANNER");
            response.sendError(403, "Access denied - scanner tool detected.");
            return;
        }

        // ── Check 3: Wrap request so body can be read twice ───
        // (ServletRequest body can only be read once by default)
        CachedBodyHttpServletRequest cachedRequest =
            new CachedBodyHttpServletRequest(request);

        // ── Check 4: Scan URL path ────────────────────────────
        if (PATH_TRAVERSAL.matcher(uri).find()) {
            log.warning("[SENTINEL] PATH_TRAVERSAL from " + ip + ": " + uri);
            actionService.respond("unknown", ip,
                new DetectionService.DetectionResult("PATH_TRAVERSAL", 85, false, true));
            response.sendError(403, "Blocked by SentinelX: PATH_TRAVERSAL");
            return;
        }

        // ── Check 5: Scan query parameters ────────────────────
        for (var entry : cachedRequest.getParameterMap().entrySet()) {
            for (String value : entry.getValue()) {
                String hit = detectPattern(value);
                if (hit != null) {
                    log.warning("[SENTINEL] " + hit + " in query param from " + ip);
                    actionService.respond("unknown", ip,
                        new DetectionService.DetectionResult(hit, 85, false, true));
                    response.sendError(403, "Blocked by SentinelX: " + hit);
                    return;
                }
            }
        }

        // ── Check 6: Scan JSON request body ───────────────────
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            String body = cachedRequest.getBody();
            String hit  = detectPattern(body);
            if (hit != null) {
                log.warning("[SENTINEL] " + hit + " in JSON body from " + ip
                    + " | body: " + body.substring(0, Math.min(body.length(), 100)));
                actionService.respond("unknown", ip,
                    new DetectionService.DetectionResult(hit, 85, false, true));
                response.sendError(403, "Blocked by SentinelX: " + hit);
                return;
            }
        }

        // ── Check 7: Increment rate-limit counter ─────────────
        detectionService.incrementRequestCount(ip);

        // All checks passed — let the request through
        chain.doFilter(cachedRequest, res);
    }

    // ── Pattern detection helper ──────────────────────────────
    private String detectPattern(String value) {
        if (value == null || value.isBlank()) return null;
        if (SQL_PATTERN.matcher(value).find()) return "INJECTION";
        if (XSS_PATTERN.matcher(value).find()) return "INJECTION";
        if (PATH_TRAVERSAL.matcher(value).find()) return "PATH_TRAVERSAL";
        return null;
    }

    private boolean isKnownScanner(String ua) {
        for (String bad : BAD_USER_AGENTS) {
            if (ua.contains(bad)) return true;
        }
        return false;
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // ─────────────────────────────────────────────────────────
    // Inner class: wraps the request so the body can be
    // read by the filter AND ALSO by the controller later.
    // Without this, once the filter reads the body,
    // the controller would get an empty stream.
    // ─────────────────────────────────────────────────────────
    private static class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

        private final byte[] cachedBody;

        public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
            super(request);
            InputStream is = request.getInputStream();
            this.cachedBody = is.readAllBytes();
        }

        public String getBody() {
            return new String(cachedBody, StandardCharsets.UTF_8);
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream bis = new ByteArrayInputStream(cachedBody);
            return new ServletInputStream() {
                public int read() { return bis.read(); }
                public boolean isFinished() { return bis.available() == 0; }
                public boolean isReady()    { return true; }
                public void setReadListener(ReadListener l) {}
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(
                new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }
}
