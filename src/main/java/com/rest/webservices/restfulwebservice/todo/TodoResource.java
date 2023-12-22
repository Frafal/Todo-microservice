package com.rest.webservices.restfulwebservice.todo;

import com.rest.webservices.restfulwebservice.todo.Todo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
public class TodoResource {

    @Autowired
    private TodoHardcodedService todoService;

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")  //prima di autorizzare il metodo controlla che l'imput metcha con l'authentication #username == authentication.name
//    @PostAuthorize("returnObject.username == John")  //controlla post methodo che il todo abbia username == John
//    @RolesAllowed({"USER", "ADMIN"})
    @Secured({"ROLE_USER", "ROLE_ADMIN"})  //analogo di RolesAllowed ma libreria differente
    public List<Todo> getAllTodos(@PathVariable String username){
        return todoService.findAll();
    }

    @GetMapping("/users/{username}/todos/{id}")
    public Todo getTodo(@PathVariable String username, @PathVariable long id){
        return todoService.findById(id);
    }

    @DeleteMapping("/users/{username}/todos/{id}")
    public ResponseEntity<Void> deleteTodo(@PathVariable String username, @PathVariable long id){
        Todo todo = todoService.deleteById(id);
        if(todo!=null){
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }

    @PutMapping("/users/{username}/todos/{id}")
    public ResponseEntity<Todo> updateTodo(@PathVariable String username, @PathVariable long id, @RequestBody Todo todo){
        Todo todoUpdated = todoService.save(todo);
        if(todoUpdated!=null){
            return new ResponseEntity<Todo>(todo, HttpStatus.OK);
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping("/users/{username}/todos")
    public ResponseEntity<Void> updateTodo(
            @PathVariable String username, @RequestBody Todo todo){
        Todo createTodo = todoService.save(todo);

        URI uri = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}").buildAndExpand(createTodo.getId()).toUri();

            return ResponseEntity.created(uri).build();
    }



}
