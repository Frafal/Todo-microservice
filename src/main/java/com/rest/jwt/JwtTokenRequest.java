package com.rest.jwt;

import lombok.*;

//@NoArgsConstructor
//@AllArgsConstructor
//@EqualsAndHashCode
//@Getter
@Data
public class JwtTokenRequest {
    private final String username;
    private final String password;
}





