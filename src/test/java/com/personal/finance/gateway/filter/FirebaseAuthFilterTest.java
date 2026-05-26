package com.personal.finance.gateway.filter;

import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.personal.finance.gateway.config.GatewayAuthProperties;
import com.personal.finance.gateway.config.InternalForwardingProperties;
import com.personal.finance.gateway.security.FirebaseTokenVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FirebaseAuthFilterTest {

    private static final String VALID_SECRET = "test-secret-must-be-at-least-32-chars-long-aaaaa";
    private static final String UID = "firebase-uid-123";

    @Mock private FirebaseTokenVerifier verifier;
    @Mock private FirebaseToken decodedToken;
    @Mock private WebFilterChain chain;

    private InternalForwardingProperties forwarding;
    private GatewayAuthProperties authProperties;
    private FirebaseAuthFilter filter;

    @BeforeEach
    void setUp() {
        forwarding = new InternalForwardingProperties();
        forwarding.setSecret(VALID_SECRET);
        authProperties = new GatewayAuthProperties();
        authProperties.setPublicPaths(List.of(
                "/authentication/v1/login/**",
                "/authentication/v1/password/**"));
        ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        filter = new FirebaseAuthFilter(verifier, forwarding, authProperties, objectMapper);
    }

    private void stubChainPassThrough() {
        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    // ── bypass paths ──────────────────────────────────────────────────────

    @Test
    void healthEndpointBypassesFilterWithNoToken() throws Exception {
        stubChainPassThrough();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain, times(1)).filter(any());
        verify(verifier, never()).verify(anyString());
    }

    @Test
    void configuredPublicPathBypassesFilter() throws Exception {
        stubChainPassThrough();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/authentication/v1/login"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain, times(1)).filter(any());
        verify(verifier, never()).verify(anyString());
    }

    @Test
    void publicPathPreservesAuthorizationHeaderForDownstreamRevalidation() throws Exception {
        stubChainPassThrough();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/authentication/v1/password/update-request")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer client.firebase.token"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        HttpHeaders forwardedHeaders = captor.getValue().getRequest().getHeaders();

        assertThat(forwardedHeaders.getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer client.firebase.token");
        assertThat(forwardedHeaders.getFirst("X-Internal-Secret")).isNull();
        assertThat(forwardedHeaders.getFirst("X-User-Id")).isNull();
        verify(verifier, never()).verify(anyString());
    }

    @Test
    void healthEndpointBypassesFilterEvenWithToken() throws Exception {
        stubChainPassThrough();
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer whatever"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain, times(1)).filter(any());
        verify(verifier, never()).verify(anyString());
    }

    // ── rejection paths ───────────────────────────────────────────────────

    @Test
    void rejectsRequestWithoutAuthorizationHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsRequestWithEmptyAuthorizationHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, ""));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsBasicAuthHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsBearerHeaderWithEmptyToken() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer "));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        when(verifier.verify(anyString()))
                .thenThrow(new RuntimeException("token expired"));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expired.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsTamperedToken() throws Exception {
        when(verifier.verify(anyString()))
                .thenThrow(new IllegalArgumentException("malformed token"));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer tampered.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsFirebaseAuthException() throws Exception {
        when(verifier.verify(anyString()))
                .thenThrow(new RuntimeException(new FirebaseAuthException(
                        com.google.firebase.ErrorCode.UNAUTHENTICATED,
                        "revoked",
                        null,
                        null,
                        com.google.firebase.auth.AuthErrorCode.REVOKED_ID_TOKEN)));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer revoked.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void unauthorizedResponseUsesJsonContentType() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.APPLICATION_JSON);
    }

    @Test
    void unauthorizedResponseUsesApiResponseEnvelope() {
        MockServerHttpRequest req = MockServerHttpRequest.get("/api/v1/accounts/me").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).isNotNull();
        assertThat(body).contains("\"success\":false");
        assertThat(body).contains("\"code\":\"AUTH_001\"");
        assertThat(body).contains("\"message\":\"Missing Authorization header\"");
        assertThat(body).contains("\"timestamp\":");
        // ensure the old envelope shape is gone
        assertThat(body).doesNotContain("\"error\":\"Unauthorized\"");
    }

    // ── happy paths ──────────────────────────────────────────────────────

    @Test
    void validTokenInvokesDownstreamChain() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of());
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain, times(1)).filter(any());
    }

    @Test
    void validTokenInjectsXUserIdHeader() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of());
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        HttpHeaders forwardedHeaders = captor.getValue().getRequest().getHeaders();

        assertThat(forwardedHeaders.getFirst("X-User-Id")).isEqualTo(UID);
        assertThat(forwardedHeaders.getFirst("X-Internal-Secret")).isEqualTo(VALID_SECRET);
    }

    @Test
    void validTokenStripsAuthorizationFromForwardedRequest() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of());
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isNull();
    }

    @Test
    void validTokenOnIngestionRouteForwardsDownstream() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of());
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/ingestion/upload")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        verify(chain, times(1)).filter(any());
    }

    @Test
    void rolesClaimIsForwardedAsCommaSeparatedHeader() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of("roles", List.of("USER", "PREMIUM")));
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        assertThat(captor.getValue().getRequest().getHeaders().getFirst("X-User-Roles"))
                .isEqualTo("USER,PREMIUM");
    }

    @Test
    void clientSuppliedIdentityHeadersAreStrippedBeforeForwarding() throws Exception {
        stubChainPassThrough();
        when(decodedToken.getUid()).thenReturn(UID);
        when(decodedToken.getClaims()).thenReturn(Map.of());
        when(verifier.verify(anyString())).thenReturn(decodedToken);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.value")
                        .header("X-User-Id", "attacker-uid")
                        .header("X-Internal-Secret", "stolen-secret")
                        .header("X-User-Roles", "ADMIN"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());
        HttpHeaders headers = captor.getValue().getRequest().getHeaders();

        assertThat(headers.getFirst("X-User-Id")).isEqualTo(UID);
        assertThat(headers.getFirst("X-Internal-Secret")).isEqualTo(VALID_SECRET);
        assertThat(headers.get("X-User-Roles")).isNull();
    }
}
