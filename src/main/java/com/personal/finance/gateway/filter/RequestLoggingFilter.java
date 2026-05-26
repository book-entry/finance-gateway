package com.personal.finance.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Logs every inbound request and its eventual response status / latency, plus the route the
 * gateway picked and the exact upstream URL it forwarded to. Runs at {@code HIGHEST_PRECEDENCE}
 * so it sees rejections written by {@link FirebaseAuthFilter} too.
 *
 * <p>Log format:
 * <pre>
 *   → POST /authentication/v1/login  from=127.0.0.1
 *   ← POST /authentication/v1/login  status=200  in=87ms  route=authentication-service  target=http://localhost:8084/authentication/v1/login
 * </pre>
 *
 * <p>If {@code route=none} on a request that should have been routed, the path didn't match any
 * predicate in {@code application.yaml}. If {@code target} has an unexpected path (e.g.
 * {@code /authentication/authentication/v1/login}) the upstream URL property is misconfigured.
 *
 * <p>Toggle the {@code com.personal.finance.gateway.filter.RequestLoggingFilter} logger to
 * {@code DEBUG} to also dump request headers (Authorization / X-Internal-Secret redacted).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestLoggingFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();
        String method = req.getMethod().name();
        String path = req.getURI().getPath();
        String query = req.getURI().getRawQuery();
        String fullPath = (query != null) ? path + "?" + query : path;
        String remote = (req.getRemoteAddress() != null)
                ? req.getRemoteAddress().getAddress().getHostAddress()
                : "unknown";

        long start = System.currentTimeMillis();
        log.info("→ {} {}  from={}", method, fullPath, remote);

        if (log.isDebugEnabled()) {
            req.getHeaders().forEach((name, values) ->
                    log.debug("   header: {}: {}", name, redact(name, values)));
        }

        return chain.filter(exchange).doFinally(signal -> {
            long elapsed = System.currentTimeMillis() - start;
            Integer status = (exchange.getResponse().getStatusCode() != null)
                    ? exchange.getResponse().getStatusCode().value()
                    : null;

            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            URI target = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR);
            String routeId = (route != null) ? route.getId() : "none";
            String targetStr = (target != null) ? target.toString() : "none";

            log.info("← {} {}  status={}  in={}ms  route={}  target={}",
                    method, fullPath, status, elapsed, routeId, targetStr);
        });
    }

    /** Redact the Authorization header value in DEBUG logs. */
    private static Object redact(String name, Object value) {
        if ("authorization".equalsIgnoreCase(name) || "x-internal-secret".equalsIgnoreCase(name)) {
            return "[REDACTED]";
        }
        return value;
    }
}
