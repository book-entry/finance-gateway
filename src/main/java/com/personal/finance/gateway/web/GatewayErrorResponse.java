package com.personal.finance.gateway.web;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

/**
 * Error-response envelope that mirrors {@code finance-common}'s
 * {@code com.personal.finance.common.web.ApiResponse} JSON shape, so frontends parse the
 * same payload regardless of whether the gateway or a downstream service authored it.
 *
 * <p>Cannot directly reuse the {@code ApiResponse} class because {@code finance-common}
 * pulls in {@code spring-boot-starter-web} (servlet/Tomcat) which conflicts with the
 * gateway's WebFlux/Netty stack.
 *
 * <h2>JSON shape</h2>
 * <pre>
 * {
 *   "success": false,
 *   "error": { "code": "AUTH_001", "message": "Authentication required" },
 *   "timestamp": "2026-05-26T13:05:06.460Z"
 * }
 * </pre>
 *
 * <p>If you add a field to {@code finance-common}'s {@code ApiResponse}, mirror it here too.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record GatewayErrorResponse(
        boolean success,
        ErrorBody error,
        Instant timestamp,
        String traceId
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ErrorBody(String code, String message) {}

    public static GatewayErrorResponse of(String code, String message) {
        return new GatewayErrorResponse(false, new ErrorBody(code, message), Instant.now(), null);
    }
}
