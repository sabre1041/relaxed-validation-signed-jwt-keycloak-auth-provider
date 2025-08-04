package com.andyserver.keycloak;

import java.security.PublicKey;
import java.util.function.BiConsumer;

import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.jose.JOSE;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;

import jakarta.ws.rs.core.Response;

public class RelaxedValidationJWTClientAuthenticator extends JWTClientAuthenticator {

    private final String providerId;
    public static final String VERIFY_TOKEN_REUSE = "verifyTokenReuse";
    public static final String VERIFY_ISSUER_SUBJECT_MATCH = "verifyIssuerSubjectMatch";

    BiConsumer<JOSE, ClientModel> DEFAULT_VALIDATOR = (jwt, client) -> {
        String rawAlgorithm = jwt.getHeader().getRawAlgorithm();

        if (rawAlgorithm.equalsIgnoreCase(Algorithm.none.name())) {
            throw new RuntimeException("Algorithm none not supported");
        }
    };

    public RelaxedValidationJWTClientAuthenticator(String providerId) {
        this.providerId = providerId;
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        RelaxedValidationJWTClientValidator validator = new RelaxedValidationJWTClientValidator(context, getId());
        if (!validator.clientAssertionParametersValidation())
            return;

        try {
            validator.readJws();
            if (!validator.validateClient())
                return;
            if (!validator.validateSignatureAlgorithm())
                return;

            RealmModel realm = validator.getRealm();
            ClientModel client = validator.getClient();
            JWSInput jws = validator.getJws();
            JsonWebToken token = validator.getToken();
            String clientAssertion = validator.getClientAssertion();

            // Get client key and validate signature
            PublicKey clientPublicKey = getSignatureValidationKey(client, context, jws);
            if (clientPublicKey == null) {
                // Error response already set to context
                return;
            }

            boolean signatureValid;
            try {
                JsonWebToken jwt = context.getSession().tokens().decodeClientJWT(clientAssertion, client,
                        (jose, validatedClient) -> {
                            DEFAULT_VALIDATOR.accept(jose, validatedClient);
                            String signatureAlgorithm = jose.getHeader().getRawAlgorithm();
                            ClientSignatureVerifierProvider signatureProvider = context.getSession()
                                    .getProvider(ClientSignatureVerifierProvider.class, signatureAlgorithm);
                            if (signatureProvider == null) {
                                throw new RuntimeException("Algorithm not supported");
                            }
                            if (!signatureProvider.isAsymmetricAlgorithm()) {
                                throw new RuntimeException("Algorithm is not asymmetric");
                            }
                        }, JsonWebToken.class);
                signatureValid = jwt != null;
            } catch (RuntimeException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new RuntimeException("Signature on JWT token failed validation", cause);
            }
            if (!signatureValid) {
                throw new RuntimeException("Signature on JWT token failed validation");
            }

            validator.validateTokenAudience(context, realm, token);

            validator.validateToken();

            validator.validateTokenReuse();

            context.success();
        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(),
                    OAuthErrorException.INVALID_CLIENT,
                    "Client authentication with signed JWT failed: " + e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
        }
    }

    @Override
    public String getId() {
        return providerId;
    }

}
