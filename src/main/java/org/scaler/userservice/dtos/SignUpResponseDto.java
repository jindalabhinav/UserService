package org.scaler.userservice.dtos;

import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;
import org.scaler.userservice.models.Role;

import java.util.List;

@Setter
@Getter
public class SignUpResponseDto {
    private String name;
    private String email;
    private Boolean isEmailVerified;
}
