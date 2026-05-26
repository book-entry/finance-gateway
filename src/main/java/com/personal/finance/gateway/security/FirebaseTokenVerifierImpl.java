package com.personal.finance.gateway.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Default {@link FirebaseTokenVerifier} that delegates to the Firebase Admin SDK.
 *
 * <p>The {@link FirebaseAuth} dependency is supplied via an {@link ObjectProvider} rather
 * than a direct {@code @Lazy} injection. The Firebase SDK ships {@code FirebaseAuth} as a
 * {@code final} class, which CGLIB cannot subclass, so a {@code @Lazy} proxy fails at startup.
 * {@link ObjectProvider} achieves the same goal — Firebase is not initialised until the first
 * call to {@link #verify(String)} — without needing a proxy.
 *
 * <p>{@code checkRevoked=true} is intentional for a financial product: when a user's account
 * is compromised and their token is revoked in the Firebase console, the revocation takes
 * effect on the next request rather than waiting up to an hour for token expiry.
 */
@Component
public class FirebaseTokenVerifierImpl implements FirebaseTokenVerifier {

    private final ObjectProvider<FirebaseAuth> firebaseAuthProvider;

    public FirebaseTokenVerifierImpl(ObjectProvider<FirebaseAuth> firebaseAuthProvider) {
        this.firebaseAuthProvider = firebaseAuthProvider;
    }

    @Override
    public FirebaseToken verify(String idToken) throws Exception {
        return firebaseAuthProvider.getObject().verifyIdToken(idToken, /* checkRevoked= */ true);
    }
}
