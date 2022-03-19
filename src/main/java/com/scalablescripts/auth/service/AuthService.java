package com.scalablescripts.auth.service;

import com.scalablescripts.auth.data.User;
import com.scalablescripts.auth.data.UserRepo;
import com.scalablescripts.auth.error.EmailAlreadyExistsError;
import com.scalablescripts.auth.error.InvalidCredentialsError;
import com.scalablescripts.auth.error.PasswordsDoNotMatchError;
import com.scalablescripts.auth.error.UserNotFoundError;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.relational.core.conversion.DbActionExecutionException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class AuthService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenSecret;
    private final String refreshTokenSecret;

    public AuthService(
            UserRepo userRepo,
            PasswordEncoder passwordEncoder,
            @Value("${application.security.access-token-secret}") String accessTokenSecret,
            @Value("${application.security.refresh-token-secret}") String refreshTokenSecret) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenSecret = accessTokenSecret;
        this.refreshTokenSecret = refreshTokenSecret;
    }

    public User register(String firstName, String lastName, String email, String password, String passwordConfirm) {
        if (!Objects.equals(password, passwordConfirm))
            throw new PasswordsDoNotMatchError();

        User user;
        try {
            user = userRepo.save(User.of(firstName, lastName, email, passwordEncoder.encode(password)));
        } catch (DbActionExecutionException exception) {
            throw new EmailAlreadyExistsError();
        }
        return user;
    }

    public Login login(String email, String password) {
        var user = userRepo.findByEmail(email)
                .orElseThrow(InvalidCredentialsError::new);

        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new InvalidCredentialsError();

        return Login.of(user.getId(), accessTokenSecret, refreshTokenSecret);
    }

    public User getUserFromToken(String token) {
        return userRepo.findById(Token.from(token, accessTokenSecret))
                .orElseThrow(UserNotFoundError::new);
    }
}
