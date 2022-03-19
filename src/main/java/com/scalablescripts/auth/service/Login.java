package com.scalablescripts.auth.service;

import lombok.Getter;

public class Login {
    @Getter
    private final Token accessToken;
    @Getter
    private final Token refreshToken;

    private Login(Token accessToken, Token refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public static Login of(Long userId, String accessSecret, String refreshSecret) {
        return new Login(
                Token.of(userId, 1L, accessSecret),
                Token.of(userId, 1440L, refreshSecret)
        );
    }
}
