package com.scalablescripts.auth.service;

import lombok.Getter;

public class Login {
    @Getter
    private final Jwt accessToken;
    @Getter
    private final Jwt refreshToken;

    private static final Long ACCESS_TOKEN_VALIDITY = 1L;
    private static final Long REFRESH_TOKEN_VALIDITY = 1440L;

    private Login(Jwt accessToken, Jwt refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public static Login of(Long userId, String accessSecret, String refreshSecret) {
        return new Login(
                Jwt.of(userId, ACCESS_TOKEN_VALIDITY, accessSecret),
                Jwt.of(userId, REFRESH_TOKEN_VALIDITY, refreshSecret)
        );
    }

    public static Login of(Long userId, String accessSecret, Jwt refreshToken) {
        return new Login(
                Jwt.of(userId,ACCESS_TOKEN_VALIDITY, accessSecret),
                refreshToken
        );
    }
}
