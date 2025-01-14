package org.scaler.userservice.security.models;


import org.scaler.userservice.models.Role;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import lombok.NoArgsConstructor;

@JsonDeserialize
@NoArgsConstructor
public class CustomGrantedAuthority implements GrantedAuthority {
    private Role role;

    public CustomGrantedAuthority(Role role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return role.getName();
    }
}
