package org.scaler.userservice.security.models;

import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Collection;

import org.scaler.userservice.models.Role;
import org.scaler.userservice.models.User;
import org.springframework.security.core.GrantedAuthority;
import java.util.List;

@JsonSerialize
@JsonDeserialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails {

    private String password;
    private String username;
    private List<CustomGrantedAuthority> authorities;

    public CustomUserDetails() {
    }

    public CustomUserDetails(User user) {
        this.password = user.getHashedPassword();
        this.username = user.getEmail();

        for(Role role: user.getRoles()){
            authorities.add(new CustomGrantedAuthority(role));
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}