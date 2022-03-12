package com.scalablescripts.auth.service;

import com.scalablescripts.auth.data.User;
import com.scalablescripts.auth.data.UserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

@Service
public class AuthService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepo userRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(String firstName, String lastName, String email, String password, String passwordConfirm) {
        if (!Objects.equals(password, passwordConfirm))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "password do not match");

        return userRepo.save(
                User.of(firstName, lastName, email, passwordEncoder.encode(password))
        );
    }

    public User login(String email, String password) {
        var user = userRepo.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid credentials"));

        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid credentials");

        return user;
    }
}
