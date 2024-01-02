package com.rest.deprecated.basic.auth;

//@RestController
//@CrossOrigin(origins = "http://localhost:4200")
public class BasicAuthenticationController {

//    @GetMapping("/basicauth")
    public AuthenticationBean basicauth(){

        return new AuthenticationBean("Yout are authenticated");
    }
}
