package com.rest.webservices.restfulwebservice.oauth.jwt;


public record JwtTokenResponse(String access_token, Integer expires_in,
                               String refresh_token, Integer refresh_expires_in, String token_type
        , Integer not_before_policy, String session_state, String scope) {


}