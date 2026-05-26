package com.personal.finance.gateway;

import com.personal.finance.gateway.config.TestFirebaseConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test that the Spring application context boots.
 *
 * <p>Uses the {@code test} profile (gateway auto-config disabled, empty Firebase credential
 * paths) and {@link TestFirebaseConfig} (mocked {@code FirebaseApp} / {@code FirebaseAuth}),
 * so the test does not require real Firebase credentials or pull in gRPC dependencies.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestFirebaseConfig.class)
class FinanceGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
