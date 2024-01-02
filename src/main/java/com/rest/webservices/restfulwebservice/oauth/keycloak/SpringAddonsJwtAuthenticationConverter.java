package com.rest.webservices.restfulwebservice.oauth.keycloak;

import com.jayway.jsonpath.JsonPath;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SpringAddonsJwtAuthenticationConverter implements Converter<Jwt, JwtAuthenticationToken> {

    @Override
    public JwtAuthenticationToken convert(@NonNull Jwt jwt) {
        final var authorities = new JwtGrantedAuthoritiesConverter().convert(jwt);

        final String username = JsonPath.read(jwt.getClaims(), "preferred_username");
        return new JwtAuthenticationToken(jwt, authorities, username);
    }

}
