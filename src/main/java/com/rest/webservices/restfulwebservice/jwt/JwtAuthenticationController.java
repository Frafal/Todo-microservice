package com.rest.webservices.restfulwebservice.jwt;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins="http://localhost:4200")
public class JwtAuthenticationController {
    
    private final JwtTokenService tokenService;
    
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationController(JwtTokenService tokenService, 
            AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
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
        
        var authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        jwtTokenRequest.getUsername(),
                        jwtTokenRequest.getPassword());

        var authentication =
                authenticationManager.authenticate(authenticationToken);
        
        var token = tokenService.generateToken(authentication);
        
        return ResponseEntity.ok(new JwtTokenResponse(token));
    }
}