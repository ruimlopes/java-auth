package com.scalablescripts.auth.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.scalablescripts.auth.data.PasswordRecovery;
import com.scalablescripts.auth.data.Token;
import com.scalablescripts.auth.data.User;
import com.scalablescripts.auth.data.UserRepo;
import com.scalablescripts.auth.error.*;
import dev.samstevens.totp.code.CodeVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.relational.core.conversion.DbActionExecutionException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Objects;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final String accessTokenSecret;
    private final String refreshTokenSecret;
    private final MailService mailService;
    private final CodeVerifier codeVerifier;
    private final String appClientId;

    public AuthService(
            UserRepo userRepo,
            PasswordEncoder passwordEncoder,
            @Value("${application.security.access-token-secret}") String accessTokenSecret,
            @Value("${application.security.refresh-token-secret}") String refreshTokenSecret,
            MailService mailService, CodeVerifier codeVerifier,
            @Value("${application.security.google-client-id}") String appClientId) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenSecret = accessTokenSecret;
        this.refreshTokenSecret = refreshTokenSecret;
        this.mailService = mailService;
        this.codeVerifier = codeVerifier;
        this.appClientId = appClientId;
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

        return getLogin(user);
    }

    public User getUserFromToken(String token) {
        return userRepo.findById(Jwt.from(token, accessTokenSecret).getUserId())
                .orElseThrow(UserNotFoundError::new);
    }

    public Login refreshAccess(String refreshToken) {
        var refreshJwt = Jwt.from(refreshToken, refreshTokenSecret);

        var user = userRepo.findByIdAndTokensRefreshTokenAndTokensExpiredAtGreaterThan(refreshJwt.getUserId(), refreshJwt.getToken(), refreshJwt.getExpiration())
                .orElseThrow(UnauthenticatedError::new);

        return Login.of(refreshJwt.getUserId(), accessTokenSecret, refreshJwt, false);
    }

    public Boolean logout(String refreshToken) {
        var refreshJwt = Jwt.from(refreshToken, refreshTokenSecret);

        var user = userRepo.findById(refreshJwt.getUserId())
                .orElseThrow(UnauthenticatedError::new);

        var tokenIsRemoved = user.removeTokenIf(token -> Objects.equals(token.refreshToken(), refreshToken));

        if (tokenIsRemoved)
            userRepo.save(user);

        return tokenIsRemoved;
    }

    public void forgot(String email, String originUrl) {
        var token = UUID.randomUUID().toString().replace("-", "");
        var user = userRepo.findByEmail(email)
                .orElseThrow(UserNotFoundError::new);

        user.addPasswordRecovery(new PasswordRecovery(token));

        mailService.sendForgotMessage(email, token, originUrl);

        userRepo.save(user);
    }

    public void reset(String token, String password, String passwordConfirm) {
        if (!Objects.equals(password, passwordConfirm))
            throw new PasswordsDoNotMatchError();

        var user = userRepo.findByPasswordRecoveriesToken(token)
                .orElseThrow(InvalidLinkError::new);

        user.setPassword(passwordEncoder.encode(password));
        user.removePasswordRecoveryIf(passwordRecovery -> Objects.equals(passwordRecovery.token(), token));

        userRepo.save(user);
    }

    public Login twoFactorLogin(Long id, String secret, String code) {
        var user = userRepo.findById(id)
                .orElseThrow(InvalidCredentialsError::new);

        var tfaSecret = !Objects.equals(user.getTfaSecret(), "") ? user.getTfaSecret() : secret;

        if (!codeVerifier.isValidCode(tfaSecret,code))
            throw new InvalidCredentialsError();

        if (Objects.equals(user.getTfaSecret(), "")) {
            user.setTfaSecret(secret);
            userRepo.save(user);
        }

        var login = Login.of(user.getId(), accessTokenSecret, refreshTokenSecret, false);
        var refreshJwt = login.getRefreshToken();

        user.addToken(new Token(refreshJwt.getToken(), refreshJwt.getIssuedAt(), refreshJwt.getExpiration()));
        userRepo.save(user);

        return login;
    }

    public Login googleAuthLogin(String token) {
        GoogleIdTokenVerifier verifier;
        GoogleIdToken idToken = null;

        try {
            verifier = new GoogleIdTokenVerifier.Builder(GoogleNetHttpTransport.newTrustedTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(appClientId))
                    .build();

            idToken = verifier.verify(token);
        } catch (GeneralSecurityException | IOException e) {
            throw new InvalidCredentialsError();
        }

        if (idToken == null)
            throw new UserNotFoundError();

        GoogleIdToken.Payload payload = idToken.getPayload();

        var email = payload.getEmail();
        var firstName = (String) payload.get("given_name");
        var lastName = (String) payload.get("family_name");

        var user = userRepo.findByEmail(email)
                .orElse(User.of(firstName, lastName, email, UUID.randomUUID().toString()));
        userRepo.save(user);

        return getLogin(user);
    }

    private Login getLogin(User user) {
        var login = Login.of(user.getId(), accessTokenSecret, refreshTokenSecret, Objects.equals(user.getTfaSecret(), ""));
        var refreshJwt = login.getRefreshToken();

        user.addToken(new Token(refreshJwt.getToken(), refreshJwt.getIssuedAt(), refreshJwt.getExpiration()));
        userRepo.save(user);

        return login;
    }
}
