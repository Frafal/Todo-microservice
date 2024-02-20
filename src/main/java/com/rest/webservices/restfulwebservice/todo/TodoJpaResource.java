package com.rest.webservices.restfulwebservice.todo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
//@Secured({"ROLE_USER", "ROLE_ADMIN"})
//@CrossOrigin(origins = "http://localhost:4200",
//        methods = {RequestMethod.GET, RequestMethod.POST,RequestMethod.POST,RequestMethod.OPTIONS, RequestMethod.DELETE},
//        exposedHeaders = {"Access-Control-Allow-Origin","Access-Control-Allow-Credentials"},
//        allowedHeaders = {"Authorization", "Origin"},
//        allowCredentials = "true")
public class TodoJpaResource {

    @Autowired
    private TodoHardcodedService todoService;

    @Autowired
    private TodoJpaRepository todoJpaRepository;

    @GetMapping("/users/{username}/todos")
//    @Secured({"REALM_ROLE_user"})
//    @PreAuthorize("#username == authentication.name")
    public List<Todo> getAllTodos(@PathVariable String username){

        return todoJpaRepository.findByUsername(username);
    }

    @GetMapping("/users/{username}/todos/{id}")
//    @Secured({"REALM_ROLE_user"})
//    @PreAuthorize("#username == authentication.name")
    public Todo getTodo(@PathVariable String username, @PathVariable long id){
        return todoJpaRepository.findById(id).get();
    }

    @DeleteMapping("/users/{username}/todos/{id}")
//    @Secured({"REALM_ROLE_user"})
//    @PreAuthorize("#username == authentication.name")
    public ResponseEntity<Void> deleteTodo(@PathVariable String username, @PathVariable long id){
        todoJpaRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/users/{username}/todos/{id}")
//    @Secured({"REALM_ROLE_user"})
//    @PreAuthorize("#username == authentication.name")
    public ResponseEntity<Todo> updateTodo(@PathVariable String username, @PathVariable long id, @RequestBody Todo todo){
//        todo.setUsername(username);
        Todo todoUpdated = todoJpaRepository.save(todo);
        return new ResponseEntity<Todo>(todo, HttpStatus.OK);

    }

    @PostMapping("/users/{username}/todos")
//    @Secured({"REALM_ROLE_user"})
//    @PreAuthorize("#username == authentication.name")
    public ResponseEntity<Void> createTodo(@PathVariable String username, @RequestBody Todo todo){
//        todo.setUsername(username);
        Todo createTodo = todoJpaRepository.save(todo);

        URI uri = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}").buildAndExpand(createTodo.getId()).toUri();

        return ResponseEntity.created(uri).build();
    }



}
