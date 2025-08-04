package com.andyserver.keycloak;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class RelaxedValidationJWTClientAuthenticationFactory implements ClientAuthenticatorFactory {

    public static final String PROVIDER_ID = "relaxed-validation-client-jwt";
    private static final RelaxedValidationJWTClientAuthenticator SINGLETON = new RelaxedValidationJWTClientAuthenticator(
            PROVIDER_ID);

    @Override
    public ClientAuthenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Relaxed Validation Signed Jwt";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates client based on signed JWT issued by client and signed with the Client private key while relaxing JWT issuer restrictions.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(RelaxedValidationJWTClientAuthenticator.VERIFY_ISSUER_SUBJECT_MATCH)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Verify Issuer and Subject Match")
                .helpText("Verifies Issuer and Subject of the JWT Match")
                .add()
                .property()
                .name(RelaxedValidationJWTClientAuthenticator.VERIFY_TOKEN_REUSE)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .label("Validate Against Token Reuse")
                .helpText("Verifies JWT Has Not Been Used by Another Authenticating Client")
                .add()
                .build();
    }

    @Override
    public ClientAuthenticator create() {
        return SINGLETON;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        Map<String, Object> props = new HashMap<>();
        props.put("client-keystore-file", "REPLACE WITH THE LOCATION OF YOUR KEYSTORE FILE");
        props.put("client-keystore-type", "jks");
        props.put("client-keystore-password", "REPLACE WITH THE KEYSTORE PASSWORD");
        props.put("client-key-password", "REPLACE WITH THE KEY PASSWORD IN KEYSTORE");
        props.put("client-key-alias", client.getClientId());
        props.put("token-timeout", 10);
        String algorithm = client.getAttribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
        if (algorithm != null) {
            props.put("algorithm", algorithm);
        }

        Map<String, Object> config = new HashMap<>();
        config.put("jwt", props);
        return config;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.PRIVATE_KEY_JWT);
            return results;
        } else {
            return Collections.emptySet();
        }
    }
}
