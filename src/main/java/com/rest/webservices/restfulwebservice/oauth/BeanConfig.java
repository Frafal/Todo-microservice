package com.rest.webservices.restfulwebservice.oauth;

import com.rest.webservices.restfulwebservice.oauth.exception.UserDefinedException;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Configuration
public class BeanConfig {
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    public WebClient webClient() {

        return WebClient.builder()
                .baseUrl("http://localhost:9090")
//                .filter(errorHandler())
//                .defaultCookie("cookie-name", "cookie-value")
//                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    //non utlizzato
//    public static ExchangeFilterFunction errorHandler() {
//        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
//            if (clientResponse.statusCode().is5xxServerError()) {
//                return clientResponse.bodyToMono(String.class)
//                        .flatMap(errorBody -> Mono.error(new RuntimeException("Logic error.")));
//            } else if (clientResponse.statusCode().is4xxClientError()) {
//                return clientResponse.bodyToMono(String.class)
//                        .flatMap(errorBody -> Mono.error(new UserDefinedException(errorBody)));
//            } else {
//                return Mono.just(clientResponse);
//            }
//        });
//    }
}
