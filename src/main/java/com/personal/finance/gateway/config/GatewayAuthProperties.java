package com.personal.finance.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Paths the {@link com.personal.finance.gateway.filter.FirebaseAuthFilter} should let through
 * <em>without</em> Firebase token validation. Matched as Ant-style patterns against the request
 * path.
 *
 * <p>Bypassed paths are <b>fully transparent</b>:
 * <ul>
 *   <li>The filter never inspects the Authorization header. A pre-token endpoint (e.g.
 *       {@code /authentication/v1/login}) is reached even with no Authorization at all.</li>
 *   <li>The Authorization header is <b>not stripped</b>; the OAuth login exchange does not need
 *       it, but a bypassed path that did its own Bearer validation would still see the token.</li>
 *   <li>{@code X-Internal-Secret} / {@code X-User-Id} / {@code X-User-Roles} are <b>not injected</b>.
 *       The receiving service must not assume gateway-trusted identity on these paths.</li>
 * </ul>
 *
 * <p>Configure in {@code application.yaml}:
 * <pre>
 * finance:
 *   gateway:
 *     public-paths:
 *       - /actuator/health
 *       - /authentication/v1/login/**
 * </pre>
 *
 * <p>{@code /actuator/health} is always treated as public regardless of configuration, so
 * liveness probes work even if the property is misconfigured.
 */
@ConfigurationProperties(prefix = "finance.gateway")
public class GatewayAuthProperties {

    /** Ant-style path patterns matched against the request URI. */
    private List<String> publicPaths = new ArrayList<>();

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = (publicPaths != null) ? publicPaths : new ArrayList<>();
    }
}
