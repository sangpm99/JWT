package com.jwt.example.JWTExample.service;

import org.springframework.stereotype.Service;
import com.jwt.example.JWTExample.models.User;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {
    private List<User> store = new ArrayList<>();

    public UserService() {
        store.add(new User(UUID.randomUUID().toString(), "User Name 1", "username1@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 2", "username2@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 3", "username3@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 4", "username4@gmail.com"));
    }

    public List<User> getUser() {
        return store;
    }
}
