package com.personal.finance.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Browser CORS for the SPA.
 *
 * <p>Registered at {@link Ordered#HIGHEST_PRECEDENCE} so it runs <em>ahead</em>
 * of {@link com.personal.finance.gateway.filter.FirebaseAuthFilter}
 * ({@code HIGHEST_PRECEDENCE + 10}). That ordering matters: a CORS preflight is
 * an {@code OPTIONS} request that carries no {@code Authorization} header, so if
 * the auth filter saw it first it would answer 401 and the browser would report
 * a CORS failure. This filter answers the preflight (and stamps the
 * {@code Access-Control-*} headers on real responses) before auth runs.
 *
 * <p>Allowed origins are configured via {@code finance.gateway.cors.allowed-origins}
 * (comma-separated). When empty, no cross-origin access is granted — same-origin
 * deployments (SPA reverse-proxied under the gateway) don't need this at all.
 */
@Configuration
public class CorsConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsWebFilter corsWebFilter(
            @Value("${finance.gateway.cors.allowed-origins:}") List<String> allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        // The SPA sends the Firebase ID token as `Authorization: Bearer …` and
        // JSON bodies, so those two headers must be allowed on the preflight.
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        // Token-in-header auth — no cookies — so credentials mode stays off.
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
