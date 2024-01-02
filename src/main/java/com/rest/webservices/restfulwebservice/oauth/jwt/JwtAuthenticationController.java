package com.rest.webservices.restfulwebservice.oauth.jwt;

import com.rest.webservices.restfulwebservice.oauth.keycloak.KeycloakConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
//import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Objects;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
public class JwtAuthenticationController {


    private final WebClient webClient;

    private final KeycloakConfiguration keycloakConfiguration;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);

    public JwtAuthenticationController(WebClient webClient, KeycloakConfiguration keycloakConfiguration) {
        this.webClient = webClient;
        this.keycloakConfiguration = keycloakConfiguration;
    }

    @PostMapping(path = "/authenticate"//,
//            consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE},
//            produces = {
//                    MediaType.APPLICATION_ATOM_XML_VALUE,
//                    MediaType.APPLICATION_JSON_VALUE
//            }
    )
    public ResponseEntity<JwtTokenResponse> generateToken(@RequestBody JwtTokenRequest jwtTokenRequest) {

        String endSessionEndpoint = keycloakConfiguration.getIssuerUri() + "/protocol/openid-connect/token";

        Mono<JwtTokenResponse> result = webClient.post()
                .uri(endSessionEndpoint)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData("client_id", keycloakConfiguration.getClientId())
                        .with("username", jwtTokenRequest.username())
                        .with("password", jwtTokenRequest.password())
                        .with("grant_type", "password"))

                .retrieve()
                .onStatus(HttpStatus.UNAUTHORIZED::equals, response -> {
                    logger.error("Could not propagate login to Keycloak");
                    return Mono.empty();
                })
                .bodyToMono(JwtTokenResponse.class);

//                .toEntity(JwtTokenResponse.class)
//                .filter(response -> response.getStatusCode().is2xxSuccessful());

        if (Objects.requireNonNull(result.block()).access_token() != null) {
            return ResponseEntity.ok(result.block());
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }


}