package com.scalablescripts.auth.service;

import com.scalablescripts.auth.data.User;
import com.scalablescripts.auth.data.UserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

@Service
public class AuthService {
    private final UserRepo userRepo;

    public AuthService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    public User register(String firstName, String lastName, String email, String password, String passwordConfirm) {
        if (!Objects.equals(password, passwordConfirm))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password do not match");

        return userRepo.save(
                User.of(firstName, lastName, email, password)
        );
    }
}
