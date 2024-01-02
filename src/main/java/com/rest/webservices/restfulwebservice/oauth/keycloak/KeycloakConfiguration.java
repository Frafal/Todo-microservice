package com.rest.webservices.restfulwebservice.oauth.keycloak;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties(prefix = "keycloak.config")
@Configuration("UserData")
@Data
public class KeycloakConfiguration {
    String clientId;
    String authorizationGrantType;
    String scope;
    String issuerUri;
    String usernameAttribute;
}



