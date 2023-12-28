package com.rest.webservices.restfulwebservice.oauth.jwt;

import com.rest.webservices.restfulwebservice.oauth.KeycloakConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins="http://localhost:4200")
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
    public ResponseEntity<JwtTokenResponse> generateToken(
            @RequestBody JwtTokenRequest jwtTokenRequest) {
//            Authentication authentication){
        
//        var authenticationToken =
//                new UsernamePasswordAuthenticationToken(
//                        jwtTokenRequest.getUsername(),
//                        jwtTokenRequest.getPassword());
//
//        var authentication =
//                authenticationManager.authenticate(authenticationToken);
//
//        webClient.
//
//        var token = tokenService.generateToken(authentication);
//
//        return ResponseEntity.ok(new JwtTokenResponse(token));
        String endSessionEndpoint = keycloakConfiguration.getIssuerUri() + "/protocol/openid-connect/token";
//        Map<String, String> bodyMap = new HashMap<>();
//        bodyMap.put("client-id",keycloakConfiguration.getClientId());
//        bodyMap.put("username",jwtTokenRequest.username());
//        bodyMap.put("password",jwtTokenRequest.password());
//        bodyMap.put("grant_type","password");


        JwtTokenResponse token = webClient.post()
                .uri(endSessionEndpoint)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
//                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                //.body(BodyInserters.fromValue(bodyMap))
                .body(BodyInserters.fromFormData("client_id",keycloakConfiguration.getClientId())
                        .with("username",jwtTokenRequest.username())
                        .with("password",jwtTokenRequest.password())
                        .with("grant_type","password"))
                .retrieve()
                .bodyToMono(JwtTokenResponse.class).block();
        logger.info("Successfulley login from Keycloak with token: " + token);
        return ResponseEntity.ok(token);
    }
}