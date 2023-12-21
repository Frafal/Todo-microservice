package com.rest.webservices.restfulwebservice.todo;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class TodoHardcodedService {

    private static List<Todo> todos = new ArrayList<Todo>();
    private static int idCounter = 0;


    static {
        todos.add(new Todo(++idCounter, "John", "Learn Spring MVC", new Date(), false));
        todos.add(new Todo(++idCounter, "John", "Learn Struts", new Date(), false));
        todos.add(new Todo(++idCounter, "John", "Learn Hibernate", new Date(), false));
        todos.add(new Todo(++idCounter, "John", "Learn Spring", new Date(), false));
    }

    public List<Todo> findAll(){
        return todos;
    }

    public Todo findById(long id){
        for(Todo todo : todos){
            if(todo.getId() == id){
                return todo;
            }
        }
        return null;
    }

    public Todo save(Todo todo){
        if(todo.getId() == -1 || todo.getId() == 0){
            todo.setId(++idCounter);
            todos.add(todo);
        }else{
            deleteById(todo.getId());
            todos.add(todo);
        }
        return todo;
    }

    public Todo deleteById(long id){
        Todo todo = findById(id);
        if(todo!=null){
            todos.remove(todo);
        }
        return todo;
    }
}
