package com.rest.deprecated.helloWorld;

import org.springframework.web.bind.annotation.*;

//Controller enable calls fron another port (4200)
@RestController
@CrossOrigin(origins = "http://localhost:4200")
public class HelloWorldController {

    //GET
    //URL - http://localhost:8080/hello-world
    //method - GET
    @RequestMapping(method = RequestMethod.GET, path = "/hello-world")
    public String helloWorld(){
        return "Hello World";
    }

    //
    @RequestMapping(method = RequestMethod.GET, path = "/hello-world-bean")
    public HelloWorldBean helloWorldBean(){
        throw new RuntimeException("Something went wrong");
//        return new HelloWorldBean("Hello World - changed");
    }

    //hello-world-bean/path-variable/admin
    @RequestMapping(method = RequestMethod.GET, path = "/hello-world/path-variable/{name}")
    public HelloWorldBean helloWorldPathVariable(@PathVariable String name){
        return new HelloWorldBean(String.format("Hello World, %s", name));
    }

}
