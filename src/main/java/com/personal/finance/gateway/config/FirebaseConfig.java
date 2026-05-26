package com.personal.finance.gateway.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

/**
 * Initialises the Firebase Admin SDK as Spring beans.
 *
 * <p>Both {@link #firebaseApp()} and {@link #firebaseAuth(FirebaseApp)} are {@link Lazy @Lazy}
 * so the SDK is not loaded until the first authenticated request. This keeps tests fast and
 * means a missing credential file does not stop the application from booting — the failure
 * is deferred until a real token actually needs verifying.
 *
 * <p>Credential resolution order:
 * <ol>
 *   <li>{@code firebase.service-account-path} — path to a JSON file on disk (preferred for prod).</li>
 *   <li>{@code firebase.credentials-json} — base64-encoded JSON inline (legacy, for backwards
 *       compatibility with the existing {@code application-local.yaml}).</li>
 *   <li>{@code GoogleCredentials.getApplicationDefault()} — uses {@code GOOGLE_APPLICATION_CREDENTIALS}
 *       or the GCE / GKE metadata server.</li>
 * </ol>
 */
@Configuration
public class FirebaseConfig {

    private static final Logger log = LoggerFactory.getLogger(FirebaseConfig.class);

    @Value("${firebase.service-account-path:}")
    private String serviceAccountPath;

    @Value("${firebase.credentials-json:}")
    private String credentialsJsonBase64;

    @Bean
    @Lazy
    public FirebaseApp firebaseApp() throws IOException {
        if (!FirebaseApp.getApps().isEmpty()) {
            log.info("Reusing existing FirebaseApp instance");
            return FirebaseApp.getInstance();
        }

        GoogleCredentials credentials = resolveCredentials();
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(credentials)
                .build();
        FirebaseApp app = FirebaseApp.initializeApp(options);
        log.info("Initialised FirebaseApp [{}]", app.getName());
        return app;
    }

    @Bean
    @Lazy
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp) {
        return FirebaseAuth.getInstance(firebaseApp);
    }

    private GoogleCredentials resolveCredentials() throws IOException {
        if (StringUtils.hasText(serviceAccountPath)) {
            log.info("Loading Firebase credentials from file: {}", serviceAccountPath);
            try (InputStream in = new FileInputStream(serviceAccountPath)) {
                return GoogleCredentials.fromStream(in);
            }
        }
        if (StringUtils.hasText(credentialsJsonBase64)) {
            log.info("Loading Firebase credentials from inline base64 property (legacy)");
            byte[] decoded = Base64.getDecoder().decode(credentialsJsonBase64);
            return GoogleCredentials.fromStream(new ByteArrayInputStream(decoded));
        }
        log.info("Loading Firebase credentials from GoogleCredentials.getApplicationDefault()");
        return GoogleCredentials.getApplicationDefault();
    }
}
