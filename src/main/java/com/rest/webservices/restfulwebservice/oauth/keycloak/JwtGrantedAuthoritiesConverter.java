package com.rest.webservices.restfulwebservice.oauth.keycloak;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.stream.Stream;

@RequiredArgsConstructor
@Component
public class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<? extends GrantedAuthority>> {

    @Override
    public Collection<? extends GrantedAuthority> convert(@NonNull Jwt jwt) {
        Stream<GrantedAuthority> authorities_realm = extractAuthorities(new String[] {"$.realm_access.roles"}, "REALM_ROLE", jwt);
        Stream<GrantedAuthority> authorities_resource = extractAuthorities(new String[] {"$.resource_access.*.roles"}, "RESOURCE_ROLE", jwt);

        return (Stream.concat(authorities_realm, authorities_resource).toList());
    }
    @SuppressWarnings({"rawtypes", "unchecked"})
    private Stream<GrantedAuthority> extractAuthorities(String[] paths, String prefix, Jwt jwt) {


       return Stream.of(paths).flatMap(claimPaths -> {
                    Object claim;
                    try {
                        claim = JsonPath.read(jwt.getClaims(), claimPaths);
                    } catch (PathNotFoundException e) {
                        claim = null;
                    }
                    if (claim == null) {
                        return Stream.empty();
                    }
                    if (claim instanceof String claimStr) {
                        return Stream.of(claimStr.split(","));
                    }
                    if (claim instanceof String[] claimArr) {
                        return Stream.of(claimArr);
                    }
                    if (Collection.class.isAssignableFrom(claim.getClass())) {
                        final var iter = ((Collection) claim).iterator();
                        if (!iter.hasNext()) {
                            return Stream.empty();
                        }
                        final var firstItem = iter.next();
                        if (firstItem instanceof String) {
                            return (Stream<String>) ((Collection) claim).stream();
                        }
                        if (Collection.class.isAssignableFrom(firstItem.getClass())) {
                            return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
                        }
                    }
                    return Stream.empty();
                })
                .map(str -> new SimpleGrantedAuthority(prefix + "_" + str))
                .map(GrantedAuthority.class::cast);
    }
}
