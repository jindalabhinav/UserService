package org.scaler.userservice.services;

import com.fasterxml.jackson.databind.ser.std.ToEmptyObjectSerializer;
import org.scaler.userservice.exceptions.IncorrectPasswordException;
import org.scaler.userservice.exceptions.TokenExpiredException;
import org.scaler.userservice.exceptions.UserAlreadyExistsException;
import org.scaler.userservice.exceptions.UserNotFoundException;
import org.scaler.userservice.models.Token;
import org.scaler.userservice.models.User;
import org.scaler.userservice.repositories.TokenRepository;
import org.scaler.userservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.apache.commons.lang3.RandomStringUtils;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserRepository userRepository;
    private TokenRepository tokenRepository;

    @Autowired
     public UserService(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository, TokenRepository tokenRepository) {
         this.bCryptPasswordEncoder = bCryptPasswordEncoder;
         this.userRepository = userRepository;
         this.tokenRepository = tokenRepository;
     }

    public User signUp(String name, String email, String password) {
        ValidateRequest(name, email, password);
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));
        user.setIsEmailVerified(false);
        return userRepository.save(user);
    }

    private void ValidateRequest(String name, String email, String password) {
        Optional<User> user = userRepository.findByEmailEquals(email);
        if (user.isPresent()) {
            throw new UserAlreadyExistsException("User with email " + email + " already exists");
        }
    }

    public Token login(String email, String password) {
        Optional<User> user = userRepository.findByEmailEquals(email);
        if (user.isEmpty()) {
            throw new UserNotFoundException("User with email " + email + " not found");
        }
        if (!bCryptPasswordEncoder.matches(password, user.get().getHashedPassword())) {
            throw new IncorrectPasswordException("Incorrect Password");
        }
        Token token = new Token();
        token.setValue(RandomStringUtils.randomAlphanumeric(128));
        LocalDateTime localDateTime = LocalDateTime.now().plusDays(1);
        Date expiryAt = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        token.setExpiryAt(expiryAt);
        token.setUser(user.get());
        token.setDeleted(false);
        return tokenRepository.save(token);
    }

    public void logout(String token) {
        Optional<Token> foundToken = tokenRepository.findByValueAndDeleted(token, false);
        if (foundToken.isEmpty()) {
            throw new UserNotFoundException("Logout failed");
        }
        Token toDelete = foundToken.get();
        toDelete.setDeleted(true);
        tokenRepository.save(toDelete);
    }

    public Token validateToken(String token) {
        Optional<Token> foundToken = tokenRepository.findByValueAndDeleted(token, false);
        if (foundToken.isEmpty())
            throw new UserNotFoundException("User doesn't exist or is logged out");

        if (foundToken.get().getExpiryAt().before(Date.from(Instant.now())))
            throw new TokenExpiredException("Token has expired");

        return foundToken.get();
    }
}
