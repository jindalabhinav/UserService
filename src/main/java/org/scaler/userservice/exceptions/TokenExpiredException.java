package org.scaler.userservice.exceptions;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String tokenHasExpired) {
        super(tokenHasExpired);
    }
}
