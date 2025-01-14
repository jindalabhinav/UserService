package org.scaler.userservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.annotation.Commit;

import java.util.UUID;

@SpringBootTest
class UserServiceApplicationTests {

    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    public UserServiceApplicationTests(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Test
    @Commit
    public void registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString()) // Generate a random UUID for the client ID
                .clientId("oidc-client") // Like ProductService could be a client for Google, Google would give ProductService a client ID
                .clientSecret("{noop}secret") // ProductService would be given a client secret by as well by Google
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Set the client authentication method
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Set the authorization grant type
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Set the refresh token grant type
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // Set the client credentials grant type
                .redirectUri("https://oauth.pstmn.io/v1/callback") // Set the redirect URI
                .postLogoutRedirectUri("https://oauth.pstmn.io/v1/callback") // Set the post logout redirect URI
                .scope(OidcScopes.OPENID) // Set the scope to "openid"
                .scope(OidcScopes.PROFILE) // Set the scope to "profile"
                .scope("ADMIN")
                .scope("STUDENT")
                .scope("MENTOR")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // Require authorization consent
                .build(); // Build the RegisteredClient instance

        registeredClientRepository.save(oidcClient);
    }
}
