package org.scaler.userservice.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration // This annotation indicates that this class is a configuration class
@EnableWebSecurity // This annotation enables Spring Security's web security support
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public SecurityConfig(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    @Order(1) // This annotation defines the sorting order of an annotated component or bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http); // Apply default security configurations for an OAuth2 authorization server
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())); // Configure the resource server to use JWTs

        return http.build(); // Build the HttpSecurity instance
    }

    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    @Order(2) // This annotation defines the sorting order of an annotated component or bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated() // Require all requests to be authenticated
                )
                .csrf().disable()
                .cors().disable()

                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults()); // Enable form-based login

        return http.build(); // Build the HttpSecurity instance
    }


    // @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    // public UserDetailsService userDetailsService() {
    //     UserDetails userDetails = User.builder()
    //             .username("user") // Set the username
    //             .password(bCryptPasswordEncoder.encode("password")) // Set the password
    //             .roles("USER") // Set the role
    //             .build(); // Build the UserDetails instance

    //     return new InMemoryUserDetailsManager(userDetails); // Return an in-memory user details manager with the created user
    // }

//    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString()) // Generate a random UUID for the client ID
//                .clientId("oidc-client") // Set the client ID
//                .clientSecret("{noop}secret") // Set the client secret
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Set the client authentication method
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Set the authorization grant type
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Set the refresh token grant type
//                .redirectUri("http://127.0.0.1:9000/login/oauth2/code/oidc-client") // Set the redirect URI
//                .postLogoutRedirectUri("http://127.0.0.1:9000/") // Set the post logout redirect URI
//                .scope(OidcScopes.OPENID) // Set the scope to "openid"
//                .scope(OidcScopes.PROFILE) // Set the scope to "profile"
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // Require authorization consent
//                .build(); // Build the RegisteredClient instance
//
//        return new InMemoryRegisteredClientRepository(oidcClient); // Return an in-memory registered client repository with the created client
//    }

    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey(); // Generate an RSA key pair
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); // Get the public key from the key pair
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate(); // Get the private key from the key pair
        RSAKey rsaKey = new RSAKey.Builder(publicKey) // Build an RSA key with the public key
                .privateKey(privateKey) // Set the private key
                .keyID(UUID.randomUUID().toString()) // Set a random UUID as the key ID
                .build(); // Build the RSA key
        JWKSet jwkSet = new JWKSet(rsaKey); // Create a JWK set with the RSA key
        return new ImmutableJWKSet<>(jwkSet); // Return an immutable JWK set with the JWK set
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); // Get an instance of a KeyPairGenerator for the RSA algorithm
            keyPairGenerator.initialize(2048); // Initialize the KeyPairGenerator with a key size of 2048 bits
            keyPair = keyPairGenerator.generateKeyPair(); // Generate a key pair
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex); // Throw an IllegalStateException if an error occurs
        }
        return keyPair; // Return the key pair
    }

    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource); // Return a JWT decoder that uses the provided JWK source to verify JWTs
    }

    @Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build(); // Return the settings for the authorization server
    }

    @Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() { 
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) { 
				context.getClaims().claims((claims) -> { 
					Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
							.stream()
							.map(c -> c.replaceFirst("^ROLE_", ""))
							.collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet)); 
					claims.put("roles", roles);
                    claims.put("ServiceRole", "ADMIN");
				});
			}
		};
	}
}