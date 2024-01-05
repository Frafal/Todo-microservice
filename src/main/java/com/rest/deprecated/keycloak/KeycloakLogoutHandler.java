package com.rest.deprecated.keycloak;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Component
public class KeycloakLogoutHandler implements LogoutHandler {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakLogoutHandler.class);
//    private final RestTemplate restTemplate;

    private final WebClient webClient;


    public KeycloakLogoutHandler(//RestTemplate restTemplate,
                                 WebClient webClient) {
        this.webClient = webClient;
//        this.restTemplate = restTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       Authentication auth) {
        logoutFromKeycloak((OidcUser) auth.getPrincipal());
    }

    private void logoutFromKeycloak(OidcUser user) {
        String endSessionEndpoint = user.getIssuer() + "/protocol/openid-connect/logout";
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", user.getIdToken().getTokenValue());
//
//        ResponseEntity<String> logoutResponse = restTemplate.getForEntity(
//                builder.toUriString(), String.class);


        Mono<String> logoutResponse = webClient.get()
                .uri(builder.toUriString())
                .retrieve()
                .bodyToMono(String.class)
                .doOnSuccess(response -> logger.info("Successfulley logged out from Keycloak"))
                .doOnError(error -> logger.error("Could not propagate logout to Keycloak"));
//
//        if (logoutResponse.getStatusCode().is2xxSuccessful()) {
//            logger.info("Successfulley logged out from Keycloak");
//        } else {
//            logger.error("Could not propagate logout to Keycloak");
//        }
    }



}
