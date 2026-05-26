package com.personal.finance.gateway.security;

import com.google.firebase.auth.FirebaseToken;

/**
 * Verifies a Firebase ID token and returns the decoded claims.
 *
 * <p>Exists as a separate interface so tests can mock token verification without
 * loading the Firebase SDK or {@link com.personal.finance.gateway.config.FirebaseConfig}.
 */
public interface FirebaseTokenVerifier {

    /**
     * @param idToken the raw token string (without the {@code Bearer } prefix)
     * @return the decoded token, never null
     * @throws Exception if the token is missing, malformed, expired, or revoked
     */
    FirebaseToken verify(String idToken) throws Exception;
}
