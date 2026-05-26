package com.personal.finance.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseToken;
import com.personal.finance.gateway.config.GatewayAuthProperties;
import com.personal.finance.gateway.config.InternalForwardingProperties;
import com.personal.finance.gateway.security.FirebaseTokenVerifier;
import com.personal.finance.gateway.web.GatewayErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Validates the {@code Authorization: Bearer <firebase-id-token>} header on inbound requests,
 * then forwards the request to the downstream service with a trusted identity envelope.
 *
 * <h2>Three request flows</h2>
 * <ol>
 *   <li><b>Public path</b> (matches {@link GatewayAuthProperties#getPublicPaths()} or is
 *       {@code /actuator/health}) — filter is fully bypassed. Authorization header passes
 *       through untouched; no identity headers are injected. Use this for pre-token endpoints
 *       (login, register, OTP) and for endpoints that do their own Bearer validation
 *       downstream (e.g. {@code /authentication/v1/password/update-request}).</li>
 *
 *   <li><b>Protected path with valid Bearer token</b> — token is validated by Firebase. The
 *       Authorization header is <em>stripped</em> and the gateway-signed envelope is injected:
 *       <ul>
 *         <li>{@code X-Internal-Secret} — from {@link InternalForwardingProperties#getSecret()}</li>
 *         <li>{@code X-User-Id} — Firebase UID</li>
 *         <li>{@code X-User-Roles} — comma-separated, from the {@code roles} custom claim</li>
 *       </ul>
 *       {@code finance-common}'s {@code InternalRequestFilter} verifies the secret on the
 *       downstream side before trusting the user-identity headers.</li>
 *
 *   <li><b>Protected path with no / invalid token</b> — 401 JSON, chain halted.</li>
 * </ol>
 *
 * <h2>Defence in depth</h2>
 * <p>Client-supplied {@code X-Internal-Secret} / {@code X-User-Id} / {@code X-User-Roles}
 * headers are stripped from the protected path's forwarded request before the gateway writes
 * its own. The gateway is the sole writer of these headers downstream.
 *
 * <p>The Firebase verify call is blocking; it is wrapped in {@link Mono#fromCallable} and
 * dispatched onto {@link Schedulers#boundedElastic()} to keep the event loop free.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class FirebaseAuthFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(FirebaseAuthFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String HEALTH_PATH = "/actuator/health";

    private final FirebaseTokenVerifier verifier;
    private final InternalForwardingProperties forwarding;
    private final ObjectMapper objectMapper;
    private final List<String> publicPaths;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public FirebaseAuthFilter(FirebaseTokenVerifier verifier,
                              InternalForwardingProperties forwarding,
                              GatewayAuthProperties authProperties,
                              ObjectMapper objectMapper) {
        this.verifier = verifier;
        this.forwarding = forwarding;
        this.objectMapper = objectMapper;
        this.publicPaths = List.copyOf(authProperties.getPublicPaths());
        log.info("FirebaseAuthFilter initialised with {} public path pattern(s): {}",
                publicPaths.size(), publicPaths);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (isPublic(path)) {
            log.info("auth bypass [public]: {} {}", request.getMethod(), path);
            return chain.filter(exchange);
        }

        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(header)) {
            return unauthorized(exchange, "AUTH_001", "Missing Authorization header");
        }
        if (!header.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "AUTH_001", "Authorization header must use Bearer scheme");
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            return unauthorized(exchange, "AUTH_001", "Bearer token is empty");
        }

        if (!forwarding.hasValidSecret()) {
            log.error("finance.gateway.internal.secret is missing or too short; refusing to forward");
            return unauthorized(exchange, "AUTH_001", "Gateway is not configured for downstream forwarding");
        }

        return Mono.fromCallable(() -> verifier.verify(token))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(decoded -> {
                    log.info("auth ok: {} {} uid={}", request.getMethod(), path, decoded.getUid());
                    return chain.filter(exchange.mutate()
                            .request(buildForwardedRequest(request, decoded))
                            .build());
                })
                .onErrorResume(ex -> {
                    log.warn("auth rejected [{} {}]: {}", request.getMethod(), path, ex.getMessage());
                    return unauthorized(exchange, "AUTH_002", "Token is invalid or expired");
                });
    }

    private boolean isPublic(String path) {
        if (HEALTH_PATH.equals(path)) {
            return true;
        }
        for (String pattern : publicPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the request that will be forwarded downstream: strips client-supplied identity
     * headers, removes the raw {@code Authorization} header, and writes the gateway-signed
     * identity envelope.
     */
    private ServerHttpRequest buildForwardedRequest(ServerHttpRequest original, FirebaseToken decoded) {
        String roles = extractRoles(decoded);
        return original.mutate()
                .headers(h -> {
                    h.remove(HttpHeaders.AUTHORIZATION);
                    h.remove(forwarding.getSecretHeader());
                    h.remove(forwarding.getUserIdHeader());
                    h.remove(forwarding.getRolesHeader());

                    h.set(forwarding.getSecretHeader(), forwarding.getSecret());
                    h.set(forwarding.getUserIdHeader(), decoded.getUid());
                    if (StringUtils.hasText(roles)) {
                        h.set(forwarding.getRolesHeader(), roles);
                    }
                })
                .build();
    }

    private String extractRoles(FirebaseToken token) {
        Object claim = token.getClaims().get("roles");
        if (claim instanceof List<?> list && !list.isEmpty()) {
            return list.stream()
                    .map(Object::toString)
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .collect(Collectors.joining(","));
        }
        return null;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String code, String message) {
        ServerHttpRequest req = exchange.getRequest();
        log.warn("auth rejected [{} {}]: {} ({})", req.getMethod(), req.getURI().getPath(), message, code);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        byte[] body = serialize(GatewayErrorResponse.of(code, message));
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    private byte[] serialize(GatewayErrorResponse payload) {
        try {
            return objectMapper.writeValueAsBytes(payload);
        } catch (JsonProcessingException ex) {
            // Falling back to a hand-rolled minimal payload keeps the gateway honest
            // even if Jackson is somehow misconfigured — the alternative would be a 500
            // that obscures the original auth failure.
            log.error("Failed to serialise GatewayErrorResponse; falling back to minimal JSON", ex);
            String fallback = "{\"success\":false,\"error\":{\"code\":\""
                    + payload.error().code() + "\",\"message\":\"serialisation failed\"}}";
            return fallback.getBytes(StandardCharsets.UTF_8);
        }
    }
}
