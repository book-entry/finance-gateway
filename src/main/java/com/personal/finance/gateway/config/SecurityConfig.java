package com.personal.finance.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Minimal reactive Spring Security configuration for the gateway.
 *
 * <p>Spring Security itself is intentionally permissive here — the real authentication
 * happens in {@link com.personal.finance.gateway.filter.FirebaseAuthFilter}, which runs
 * at {@code HIGHEST_PRECEDENCE} and rejects unauthenticated requests before they reach
 * the routing layer. This config disables the default login pages and CSRF protection
 * that would otherwise interfere with a token-based API gateway.
 */
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties({InternalForwardingProperties.class, GatewayAuthProperties.class})
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/health").permitAll()
                        .anyExchange().permitAll())
                .build();
    }
}
