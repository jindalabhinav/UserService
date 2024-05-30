package org.scaler.userservice.controllers.advices;

import org.scaler.userservice.controllers.UserController;
import org.scaler.userservice.dtos.ExceptionDto;
import org.scaler.userservice.exceptions.IncorrectPasswordException;
import org.scaler.userservice.exceptions.TokenExpiredException;
import org.scaler.userservice.exceptions.UserAlreadyExistsException;
import org.scaler.userservice.exceptions.UserNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice(assignableTypes = UserController.class)
public class UserControllerAdvice {
    @ExceptionHandler({UserAlreadyExistsException.class, UserNotFoundException.class, IncorrectPasswordException.class, TokenExpiredException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public ExceptionDto handleUserExceptions(RuntimeException e) {
        ExceptionDto exceptionDto = new ExceptionDto();
        exceptionDto.setMessage(e.getMessage());
        exceptionDto.setStatus("Failure");
        return exceptionDto;
    }
}