package com.personal.finance.gateway.config;

import com.personal.finance.gateway.filter.FirebaseAuthFilter;
import com.personal.finance.gateway.security.FirebaseTokenVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

@WebFluxTest
@Import({SecurityConfig.class, FirebaseAuthFilter.class, TestFirebaseConfig.class})
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private FirebaseTokenVerifier firebaseTokenVerifier;

    @Test
    void actuatorHealthIsReachableWithoutToken() {
        webTestClient.get().uri("/actuator/health")
                .exchange()
                .expectStatus()
                .value(status -> {
                    assert status != HttpStatus.UNAUTHORIZED.value();
                    assert status != HttpStatus.FORBIDDEN.value();
                });
    }

    @Test
    void apiEndpointWithoutTokenReturns401() {
        webTestClient.get().uri("/api/v1/accounts/me")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
