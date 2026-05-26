package com.personal.finance.gateway.config;

import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Replaces the real {@link FirebaseConfig} beans with Mockito mocks so that tests can load
 * a Spring context without needing real Firebase credentials.
 *
 * <p>Import in a test with {@code @Import(TestFirebaseConfig.class)}. The {@link Primary}
 * markers ensure these mocks win over any beans the production config might still register.
 */
@TestConfiguration
public class TestFirebaseConfig {

    @Bean
    @Primary
    public FirebaseApp firebaseApp() {
        return Mockito.mock(FirebaseApp.class);
    }

    @Bean
    @Primary
    public FirebaseAuth firebaseAuth() {
        return Mockito.mock(FirebaseAuth.class);
    }
}
