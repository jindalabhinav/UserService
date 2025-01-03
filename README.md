# Authentication and Authorization

Imagine you're at a Hospital, anyone can go in provided they show a valid ID card. But not everyone can access the ICU, only the doctors and nurses can. This is what Authentication and Authorization is all about.

Imagine you're roaming around in the office. The ID card gives us access to the building, but not every room is accessible by scanning the ID card.

- **Authentication** - User Identity, Who is the User
- **Authorization** - User level permission to perform an operation, Role of the User 
  - RBAC - Role Based Access Control
    - Roles can help us verify the authority of a user to perform an action.

## JWT (JSON Web Token)

- Signup
  - Email | Password --> Identity in the Application
  - Verification needed: Email based link/OTP (not any random person can sign up using any email)
- Login
  - Email | Password --> Sent to Server --> Success or Failure
    - Checked against some User Table having Email and Password
    - Passwords cannot be stored in plain text. They need to be hashed.
    - Many users can have the same password, so a simple hashing will generate the same hash for the same password. Which if leaked, can leak the password of many users.
    - So, we use a salt. A random string that is added to the password before hashing. This makes the hash unique for the same password. e.g., [BCryptr Algorithm](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)
- Checkout
  - We know that HTTP calls are stateless. So do we need to log in again to check out? Or for any other operation? We basically have to verify our identity for every operation?
  - Since the credentials are stored in the Db, we have to make a lot of Db calls to verify the identity (including Hashing for passwords using algorithms like BCrypt). This is not efficient.
  - We can associate these HTTP calls with a Token which contains some basic information about the current session and basically acts as a temporary password that can be validated with Db. But we still haven't solved the problem of eliminating the Db calls.
  - But what if all the information is stored in the Token itself? Like the User ID, Role, ExpirationTime, etc., we don't have to go to the Db and verify. This is JWT (JSON Web Token). 

### Encoding vs Hashing

- **Encoding** - Convert data into a particular format using a scheme. It can be easily reversed. e.g., Base64 Encoding
- **Hashing** - Convert data into a fixed length hash. It cannot be reversed. e.g., BCrypt Algorithm
  - We also sometimes see that multiple inputs can have the same hash. This is called a collision. Hence, we cannot reverse the hash to get the original input.

### How is the token generated?

We create a JSON of all the properties that might be useful for the server to validate the user and their permissions. For e.g., we can have the userId, email, role, expirationTime, etc., and we encode this JSON using base64 encoding. This is the token that is sent to the client. The client sends this token to the server for every operation. The server decodes the token and verifies the user and their permissions. This way, we don't have to make Db calls for every operation.

But this way if someone gets access to this token, maybe from the cookies, they can easily impersonate the user (since it can be decoded), change the access level by changing the role, etc. **How can the server verify that the token is not tampered with?**

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

**Note:** In some authentication systems, a pair of keys (public and private) is used instead of a single secret key. This is known as asymmetric cryptography.  In the context of JWT, there are two types of algorithms that can be used for signing the token:
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

Here's an example of a JWT token and its decoded form.  A JWT token typically looks like this:

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

When we log in to a website, we often see an option to login using Google, Facebook, etc. Now if each website has to maintain its own login system, it is a lot of work. We need some standardization. 

This is OAuth. It is an open standard for access delegation, commonly used as a way for Internet users to grant websites or applications access to their information on other websites but without giving them the passwords.

Now, in an application consisting of multiple microservices, we don't want to authenticate the user in each microservice. We create a separate service for authentication which is responsible for authenticating the user and generating a token. This token is then used by all the other microservices to authenticate the user.

![img.png](img.png)

In case of login via Google, Facebook, etc., the user is redirected to the respective website for authentication, and they act as the Auth Servers. Once the user is authenticated, the Auth Server sends a token to the application which is then used to authenticate the user.

We can either have our own Auth servers, or use Google and Facebook as Auth servers. This is where OAuth comes into play. It is a standard that is followed by all the Auth servers.

- OAuth is an industry-standard protocol for authorization.
- Defines the API contract for Authentication and Authorization.

### How does it work?

Participants in OAuth:

- **User**: Person who wants to access the resources.
- **Authorization** Server: The server that authenticates the user and issues the token.
- **Resource Server**: The server that has the resources that the user wants to access.

We sometimes see a popup after clicking on the Google login button while signing up. This is the consent screen. It asks the user if they want to share their information with the application. Once the user agrees, the Auth server sends a token to the application, as well as the user's information (like email, name, etc.) for signup. Basically filling like an Authorization form.

![img_1.png](img_1.png)

## Symmetric vs Asymmetric Encryption

- **Symmetric Encryption**: The same key is used for both encryption and decryption. It is faster and simpler but requires the key to be shared between the sender and receiver. e.g., AES, DES, etc.
- **Asymmetric Encryption**: Two keys are used - a public key for encryption and a private key for decryption. It is slower and more complex but provides better security. e.g., RSA, ECC, etc.
  - Public key is used to encrypt the data and the private key is used to decrypt it.
  - The private key is kept secret and is never shared.
  - The public key can be shared with anyone who wants to send encrypted data to the owner of the private key.