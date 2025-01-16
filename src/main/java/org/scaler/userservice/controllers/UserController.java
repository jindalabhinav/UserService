package org.scaler.userservice.controllers;

import lombok.NonNull;
import org.scaler.userservice.dtos.LoginRequestDto;
import org.scaler.userservice.dtos.LogoutRequestDto;
import org.scaler.userservice.dtos.SignUpRequestDto;
import org.scaler.userservice.dtos.SignUpResponseDto;
import org.scaler.userservice.models.Token;
import org.scaler.userservice.models.User;
import org.scaler.userservice.services.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public Token login(@RequestBody LoginRequestDto requestDto) {
        return userService.login(requestDto.getEmail(), requestDto.getPassword());
    }

    @PostMapping("/signup")
    public SignUpResponseDto signUp(@RequestBody SignUpRequestDto signUpRequestDto) {
        User savedUser = userService.signUp(signUpRequestDto.getName(), signUpRequestDto.getEmail(), signUpRequestDto.getPassword());
        return GetSignUpResponseDtoFromUser(savedUser);
    }

    private SignUpResponseDto GetSignUpResponseDtoFromUser(User savedUser) {
        SignUpResponseDto signUpResponseDto = new SignUpResponseDto();
        signUpResponseDto.setName(savedUser.getName());
        signUpResponseDto.setEmail(savedUser.getEmail());
        signUpResponseDto.setIsEmailVerified(savedUser.getIsEmailVerified());
        return signUpResponseDto;
    }

    @PostMapping("logout")
    public void logout(@RequestBody LogoutRequestDto requestDto) {
        userService.logout(requestDto.getToken());
    }

    @GetMapping("validateToken/{token}")
    public Token validateToken(@PathVariable("token") @NonNull String token) {
        return userService.validateToken(token);
    }

    @GetMapping()
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }
}
