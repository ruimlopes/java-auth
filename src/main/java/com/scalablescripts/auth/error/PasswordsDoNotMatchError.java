package com.scalablescripts.auth.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class PasswordsDoNotMatchError extends ResponseStatusException {
    public PasswordsDoNotMatchError() {
        super(HttpStatus.BAD_REQUEST, "passwords do not match");
    }
}
