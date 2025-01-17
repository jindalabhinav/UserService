# Authentication and Authorization

Imagine you're at a hospital. Anyone can enter provided they show a valid ID card, but not everyone can access the ICU; only doctors and nurses can. This is what Authentication and Authorization is all about.

Imagine you're roaming around in an office. The ID card gives you access to the building, but not every room is accessible by scanning the ID card.

- **Authentication** - User Identity, Who is the User
- **Authorization** - User level permission to perform an operation, Role of the User 
  - RBAC - Role Based Access Control
    - Roles can help us verify the authority of a user to perform an action.

## JWT (JSON Web Token)

- **Signup**
  - Email | Password --> Identity in the Application
  - Verification needed: Email-based link/OTP (not any random person can sign up using any email)
- **Login**
  - Email | Password --> Sent to Server --> Success or Failure
    - Checked against some User Table having Email and Password
    - Passwords cannot be stored in plain text. They need to be hashed.
    - Many users can have the same password, so a simple hashing will generate the same hash for the same password. If leaked, it can expose the password of many users.
    - So, we use a salt. A random string that is added to the password before hashing. This makes the hash unique for the same password. e.g., [BCrypt Algorithm](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)
- **Checkout**
  - HTTP calls are stateless. Do we need to log in again to check out or for any other operation? We basically have to verify our identity for every operation.
  - Since the credentials are stored in the DB, we have to make a lot of DB calls to verify the identity (including hashing for passwords using algorithms like BCrypt). This is not efficient.
  - We can associate these HTTP calls with a token that contains some basic information about the current session and acts as a temporary password that can be validated with the DB. But we still haven't solved the problem of eliminating the DB calls.
  - What if all the information is stored in the token itself? Like the User ID, Role, ExpirationTime, etc. We don't have to go to the DB and verify. This is JWT (JSON Web Token).

### Encoding vs Hashing

- **Encoding** - Convert data into a particular format using a scheme. It can be easily reversed. e.g., Base64 Encoding
- **Hashing** - Convert data into a fixed-length hash. It cannot be reversed. e.g., BCrypt Algorithm
  - Sometimes multiple inputs can have the same hash. This is called a collision. Hence, we cannot reverse the hash to get the original input.

### How is the token generated?

We create a JSON of all the properties that might be useful for the server to validate the user and their permissions. For example, we can have the userId, email, role, expirationTime, etc., and we encode this JSON using base64 encoding. This is the token that is sent to the client. The client sends this token to the server for every operation. The server decodes the token and verifies the user and their permissions. This way, we don't have to make DB calls for every operation.

But if someone gets access to this token, maybe from the cookies, they can easily impersonate the user (since it can be decoded), change the access level by changing the role, etc. **How can the server verify that the token is not tampered with?**

We can use some sort of signature in the token and verify it on the server. This means,

- When a login request is received by the server, it verifies the user's credentials.
- If the credentials are valid, the server creates a payload, which is a JSON object that contains information about the user (like user ID, role, etc.).
- This payload is then Base64Url encoded to form the second part of the JWT.
- The server also creates a header, which is another JSON object that describes the token and the algorithm used to sign it. This header is also Base64Url encoded to form the first part of the JWT.
- The server then creates a signature by hashing the combination of the encoded header, the encoded payload, and a secret key using an algorithm like HMAC. This signature forms the third part of the JWT.
- The three parts (encoded header, encoded payload, and signature) are combined with periods (.) in between to form the JWT.
- This JWT is then sent to the client, which can use it to authenticate subsequent requests.

The client does not have the secret key. The secret key is only known to the server and is used to verify that the token sent by the client hasn't been tampered with. When the server receives a request with a JWT, it can decode the header and payload, but it verifies the signature using the secret key. If the verification is successful, the server trusts the data in the token and processes the request. If the verification fails, the server rejects the request.

> How is the key present with the server used to verify an incoming token?

The server uses the secret key to verify an incoming token by following these steps:

- The server receives the token from the client. The token is a string that consists of three parts separated by periods (.) - the encoded header, the encoded payload, and the signature.
- The server splits the token into these three parts.
- The server Base64Url decodes the header and the payload. This gives the server the information about the token and the user.
- The server then takes the encoded header and the encoded payload, combines them with a period (.), and hashes this combination with the secret key using the same algorithm that was used to create the signature. This gives the server a signature that it can compare with the signature that came with the token.
- If the signature created by the server matches the signature that came with the token, the server knows that the token hasn't been tampered with and trusts the data in the token. If the signatures don't match, the server rejects the request because it means that the token may have been tampered with.

Here's a simple pseudocode representation of the process:

```javascript
function verifyToken(token, secretKey) {
  // Split the token into three parts
  let [encodedHeader, encodedPayload, signature] = token.split('.');

  // Combine the encoded header and payload with a period (.)
  let data = `${encodedHeader}.${encodedPayload}`;

  // Hash the data with the secret key
  let newSignature = hash(data, secretKey);

  // Compare the new signature with the signature from the token
  if (newSignature === signature) {
    return true;
  } else {
    return false;
  }
}
```

#### Symmetric vs Asymmetric Authentication

In some authentication systems, a pair of keys (public and private) is used instead of a single secret key. This is known as asymmetric cryptography. In the context of JWT, there are two types of algorithms that can be used for signing the token:
1. HMAC (Hash-based Message Authentication Code): This is a symmetric algorithm, which means it uses the same secret key for signing the token and verifying it. The secret key is known only to the server.
2. RSA (Rivest–Shamir–Adleman) or ECDSA (Elliptic Curve Digital Signature Algorithm): These are asymmetric algorithms, which means they use a pair of keys - a private key and a public key. The private key is used to sign the token and the public key is used to verify it. The private key is kept secret on the server, while the public key can be distributed to anyone who needs to verify the token.

The choice between symmetric and asymmetric algorithms depends on your specific use case. HMAC is simpler and faster, but it requires the server to share its secret key with any other systems that need to verify the token. RSA and ECDSA are more complex and slower, but they allow the server to keep its private key secret and share only the public key.

RSA is often preferred over HMAC in scenarios where you want to separate the ability to verify a token from the ability to issue a token.

Both HMAC and RSA/ECDSA signed tokens are self-validating. This means that all the information needed to validate the token is contained within the token itself.

For HMAC, the server uses the same secret key to generate and verify the signature.

For RSA/ECDSA, the server uses the private key to generate the signature and the corresponding public key to verify it.

In both cases, the server can verify the token without needing to store any additional information or make any database queries, which is why these tokens are considered self-validating.

### JWT Summary

- **Header** - Contains the type of token and the algorithm used to sign it.
- **Payload** - Contains the claims. Claims are statements about an entity (typically, the user) and additional data. There are three types of claims: registered, public, and private claims.
  - Registered claims: These are a set of predefined claims which are not mandatory but recommended, to provide a set of useful, interoperable claims. Some of them are: iss (issuer), exp (expiration time), sub (subject), aud (audience), and others.
  - Public claims: These can be defined at will by those using JWTs.
  - Private claims: These are the custom claims created to share information between parties that agree on using them.
- **Signature** - To create the signature part you have to take the encoded header, the encoded payload, a secret, the algorithm specified in the header, and sign that.

Here's an example of a JWT token and its decoded form. A JWT token typically looks like this:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

This token is divided into three parts, separated by periods (.):  

- **Header**: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`
- **Payload**: `eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ`
- **Signature**: `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

Each part is Base64Url encoded. When we decode the Header and Payload, we get:

Header (Decoded):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload (Decoded):
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

The Header indicates that the token is a JWT and it was signed using the HMAC SHA256 algorithm. The Payload contains claims about the user. In this case, the user's ID (`sub`), name (`name`), and the time the token was issued (`iat`). The Signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

## OAuth (Open Authorization)

When we log in to a website, we often see an option to log in using Google, Facebook, etc. If each website had to maintain its own login system, it would be a lot of work. We need some standardization.

This is OAuth. It is an open standard for access delegation, commonly used as a way for Internet users to grant websites or applications access to their information on other websites without giving them the passwords.

In an application consisting of multiple microservices, we don't want to authenticate the user in each microservice. We create a separate service for authentication which is responsible for authenticating the user and generating a token. This token is then used by all the other microservices to authenticate the user.

![img.png](img.png)

In the case of login via Google, Facebook, etc., the user is redirected to the respective website for authentication, and they act as the Auth Servers. Once the user is authenticated, the Auth Server sends a token to the application which is then used to authenticate the user.

We can either have our own Auth servers or use Google and Facebook as Auth servers. This is where OAuth comes into play. It is a standard that is followed by all the Auth servers.

- OAuth is an industry-standard protocol for authorization.
- Defines the API contract for Authentication and Authorization.

### How does it work?

Participants in OAuth:

- **User**: Person who wants to access the resources.
- **Authorization Server**: The server that authenticates the user and issues the token.
- **Resource Server**: The server that has the resources that the user wants to access.

We sometimes see a popup after clicking on the Google login button while signing up. This is the consent screen. It asks the user if they want to share their information with the application. Once the user agrees, the Auth server sends a token to the application, as well as the user's information (like email, name, etc.) for signup. Basically filling like an Authorization form.

![img_1.png](img_1.png)

## Manual Authorization

We've used the manual way of implementing Authorization by using the following code blocks:

```java
// ProductController

@GetMapping("/{id}")
public Product getProductById(@RequestHeader("Authorization") String token,
                              @PathVariable("id") Long id) throws AccessDeniedException {
    if (!authenticationService.authenticate(token)) {
        throw new AccessDeniedException("You're not authorized to perform this operation");
    }
    return productService.getProductById(id);
}
```

```java
// ProductService

private final String url = "http://localhost:9000/users/validateToken/{token}";

public boolean authenticate(String token) {
    ResponseEntity<Token> responseEntity = restTemplate.getForEntity(url, Token.class, token);
    return responseEntity.getBody() != null;
}
```

```java
// UserService

public Token validateToken(String token) {
    Optional<Token> foundToken = tokenRepository.findByValueAndDeleted(token, false);
    if (foundToken.isEmpty())
        throw new UserNotFoundException("User doesn't exist or is logged out");

    if (foundToken.get().getExpiryAt().before(Date.from(Instant.now())))
        throw new TokenExpiredException("Token has expired");

    return foundToken.get();
}
```

How can we implement this using the spring libraries so that we don't have to implement Auth ourselves?

## Authorization using Spring Authorization Server

We can refer to how to get started with Spring Authorization Server from [this](https://docs.spring.io/spring-authorization-server/reference/getting-started.html) link.

We add all the necessary code blocks from the guide mentioned above and run the User Service. Now on hitting any of the existing APIs like (`/login`), we see an HTML getting returned instead of the JSON response, prompting us to log in using a username and password.

![alt text](image-1.png)

Now by default, spring uses an `InMemoryUserDetailsManager`, but we want to get the details from the database. So let's explore Spring Auth Server with JPA.

## Spring Auth Server with JPA

Reference: https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html

The very first thing required here is to create entities for:
- Client
- Authorization
- AuthorizationConsent

Then we create the repositories to add this information to the database. These classes are also present in the guide above. Once done, we'll have the following Repositories:
- ClientRepository
- AuthorizationRepository
- AuthorizationConsentRepository

Following services are created that make use of the repositories above:
- JpaRegisteredClientRepository
- JpaOAuth2AuthorizationService
- JpaOAuth2AuthorizationConsentService

Once we're done creating the required classes, we can register a new client using the code below:

```java
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
```

The code above supports 3 grant-types, i.e., `AUTHORIZATION_CODE`, `CLIENT_CREDENTIALS`, `REFRESH_TOKEN`.

### Understanding Grant Types

#### AUTHORIZATION_CODE
The Authorization Code grant type is used by confidential and public clients to exchange an authorization code for an access token. It is the most common OAuth 2.0 flow and is used for server-side applications.

1. **Client:** The application requesting access to the user's resources.
2. **Authorization Server:** The server that authenticates the user and issues the authorization code.
3. **Resource Server:** The server hosting the protected resources.

**Flow:**

1. The client redirects the user to the authorization server.
2. The user logs in and authorizes the client.
3. The authorization server redirects the user back to the client with an authorization code.
4. The client exchanges the authorization code for an access token.

![alt text](image-2.png)

#### CLIENT_CREDENTIALS
The Client Credentials grant type is used by clients to obtain an access token outside of the context of a user. This is typically used for machine-to-machine (M2M) applications.

1. **Client:** The application requesting access to the resources.
2. **Authorization Server:** The server that issues the access token.

**Flow:**

1. The client authenticates with the authorization server using its client ID and client secret.
2. The authorization server issues an access token directly to the client.

#### REFRESH_TOKEN
The Refresh Token grant type is used to obtain a new access token by using a refresh token. This allows clients to continue to have a valid access token without further interaction with the user.

1. **Client:** The application requesting a new access token.
2. **Authorization Server:** The server that issues the new access token.

**Flow:**

1. The client sends the refresh token to the authorization server.
2. The authorization server validates the refresh token and issues a new access token.

### `UserDetailsService`

```java
@Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
public UserDetailsService userDetailsService() {
  UserDetails userDetails = User.builder()
          .username("user") // Set the username
          .password(bCryptPasswordEncoder.encode("password")) // Set the password
          .roles("USER") // Set the role
          .build(); // Build the UserDetails instance

  return new InMemoryUserDetailsManager(userDetails); // Return an in-memory user details manager with the created user
}
```

#### `UserDetailsService` Interface

- A core interface in Spring Security used to retrieve user-related data.
- It has a single method, `loadUserByUsername(String username)`, which is used to look up the user based on the username.

#### Usage
- **Authentication**
  - When a user tries to authenticate, Spring Security will use the UserDetailsService to load the user details by username.
  - The InMemoryUserDetailsManager will return the UserDetails instance if the username matches.
- **Authorization**
  - The roles and authorities defined in the UserDetails instance are used to determine what actions the authenticated user is allowed to perform.

> How do we make this Database-driven instead of using an In-Memory store?

Reference: https://www.baeldung.com/spring-security-authentication-with-a-database

### Claims in JWT

Claims in JWT (JSON Web Token) are pieces of information asserted about a subject (typically the user) and are encoded as a JSON object. These claims are used to share information between parties in a secure and compact manner.

**Types of Claims:**
- **Registered Claims:** Predefined claims that are recommended to provide a set of useful, interoperable claims.
  - `iss` (Issuer): Identifies the principal that issued the JWT.
  - `sub` (Subject): Identifies the principal that is the subject of the JWT.
  - `aud` (Audience): Identifies the recipients that the JWT is intended for.
  - `exp` (Expiration Time): Identifies the expiration time on or after which the JWT must not be accepted for processing.
  - `nbf` (Not Before): Identifies the time before which the JWT must not be accepted for processing.
  - `iat` (Issued At): Identifies the time at which the JWT was issued.
  - `jti` (JWT ID): Provides a unique identifier for the JWT.
- **Public Claims:** Custom claims that can be defined by the users to share information. These should be collision-resistant to avoid conflicts.
  - Example: `name`, `email`, `role`
- **Private Claims:** Custom claims that are used to share information between parties that agree on using them and are not intended to be shared publicly.
  - Example: `userId`, `sessionId`

**Example of a JWT Payload with Claims:**

```java
{
  "iss": "auth.example.com",
  "sub": "user@example.com",
  "aud": "example.com",
  "exp": 1618888399,
  "iat": 1618884799,
  "jti": "unique-jwt-id",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "role": "admin"
}
```

> How do we add custom claims to JWT?

Reference: https://docs.spring.io/spring-authorization-server/reference/guides/how-to-custom-claims-authorities.html

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() { 
    return (context) -> {
        // Check if the token type is an access token
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) { 
            // Customize the claims in the token
            context.getClaims().claims((claims) -> { 
                // Extract roles from the principal's authorities, remove the "ROLE_" prefix, and collect them into an unmodifiable set
                Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                    .stream()
                    .map(c -> c.replaceFirst("^ROLE_", ""))
                    .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet)); 
                
                // Add the roles to the claims
                claims.put("roles", roles);
                
                // Add a custom claim "ServiceRole" with the value "ADMIN"
                claims.put("ServiceRole", "ADMIN");
            });
        }
    };
}
```

### OAuth 2.0 Resource Server With Spring Security

> What Is a Resource Server?

In the context of OAuth 2.0, a resource server is an application that protects resources via OAuth tokens. These tokens are issued by an authorization server, typically to a client application. The job of the resource server is to validate the token before serving a resource to the client.

A token’s validity is determined by several things:
- Did this token come from the configured authorization server?
- Is it unexpired?
- Is this resource server its intended audience?
- Does the token have the required authority to access the requested resource?

#### Maven Dependencies

```maven
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    <version>3.4.1</version>
</dependency>
```

#### Security Configuration

The moment we add the below config, all our endpoints within this service will be authenticated and will start throwing a `401 Unauthorized` error.

```java
@Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
        throws Exception {
    http
            .authorizeHttpRequests((authorize) -> authorize
                    .anyRequest().authenticated() // Require all requests to be authenticated
            )
            .csrf().disable()
            .cors().disable()

    return http.build(); // Build the HttpSecurity instance
}
```

We can add some requestMatchers to allow users with certain authority to access particular resources:

```java
@Bean // This annotation indicates that a method produces a bean to be managed by the Spring container
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
        throws Exception {
    http
            .authorizeHttpRequests((authorize) -> authorize
                    .requestMatchers("/products/{id}").hasAuthority("CUSTOMER") // Only users with CUSTOMER authority can access /products/{id}
                    .requestMatchers("/products").hasAuthority("ADMIN") // Only users with ADMIN authority can access /products
                    .anyRequest().authenticated() // Require all requests to be authenticated
            )
            .csrf().disable()
            .cors().disable()

    return http.build(); // Build the HttpSecurity instance
}
```

The Resource Server can also make use of the custom claims set in the token to derive Authorities:

```java
@Bean
public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
    grantedAuthoritiesConverter.setAuthoritiesClaimName("ServiceRole");

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    return jwtAuthenticationConverter;
}
```

To make use of the `jwtAuthenticationConverter` in the `defaultSecurityFilterChain`, we need to configure the `HttpSecurity` object to use the `JwtAuthenticationConverter` for JWT-based authentication.

```java
@Bean
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/products/{id}").hasAuthority("CUSTOMER")
            .requestMatchers("/products").hasAuthority("ADMIN")
            .anyRequest().authenticated()
        )
        .csrf().disable()
        .cors().disable()
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
            )
        );

    return http.build();
}
```

