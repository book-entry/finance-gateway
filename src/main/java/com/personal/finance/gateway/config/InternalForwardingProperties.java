package com.personal.finance.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * Configuration for the headers the gateway injects when forwarding an authenticated
 * request to a downstream service.
 *
 * <p>The {@code secret} is the trust boundary between the gateway and downstream services.
 * Downstream services verify it with {@code finance-common}'s {@code InternalRequestFilter}
 * before trusting {@code X-User-Id}. The same value MUST be configured identically on the
 * gateway ({@code finance.gateway.internal.secret}) and on every downstream service
 * ({@code finance.security.internal.secret}).
 *
 * <p>Header names default to the values {@code InternalRequestFilter} expects, so most
 * deployments only need to set {@code secret}.
 *
 * <p>Generate a secret with: {@code openssl rand -hex 32}
 */
@ConfigurationProperties(prefix = "finance.gateway.internal")
public class InternalForwardingProperties {

    private String secret;
    private String secretHeader = "X-Internal-Secret";
    private String userIdHeader = "X-User-Id";
    private String rolesHeader = "X-User-Roles";

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getSecretHeader() {
        return secretHeader;
    }

    public void setSecretHeader(String secretHeader) {
        this.secretHeader = secretHeader;
    }

    public String getUserIdHeader() {
        return userIdHeader;
    }

    public void setUserIdHeader(String userIdHeader) {
        this.userIdHeader = userIdHeader;
    }

    public String getRolesHeader() {
        return rolesHeader;
    }

    public void setRolesHeader(String rolesHeader) {
        this.rolesHeader = rolesHeader;
    }

    /**
     * Returns true once a valid (non-empty, &ge;32 char) secret has been configured.
     * Callers should treat a false result as misconfiguration and fail the request.
     */
    public boolean hasValidSecret() {
        return StringUtils.hasText(secret) && secret.length() >= 32;
    }
}
