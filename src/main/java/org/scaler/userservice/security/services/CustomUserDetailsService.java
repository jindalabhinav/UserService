package org.scaler.userservice.security.services;

import org.scaler.userservice.models.User;
import org.scaler.userservice.repositories.UserRepository;
import org.scaler.userservice.security.models.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class CustomUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmailEquals(username);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }
        return new CustomUserDetails(userOptional.get());
    }
}
