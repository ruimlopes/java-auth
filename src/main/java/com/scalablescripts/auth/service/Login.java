package com.scalablescripts.auth.service;

import com.google.common.io.BaseEncoding;
import lombok.Getter;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class Login {
    @Getter
    private final Jwt accessToken;
    @Getter
    private final Jwt refreshToken;
    @Getter
    private final String otpSecret;
    @Getter
    private final String otpUrl;

    private static final Long ACCESS_TOKEN_VALIDITY = 1L;
    private static final Long REFRESH_TOKEN_VALIDITY = 1440L;

    private Login(Jwt accessToken, Jwt refreshToken, String otpSecret, String otpUrl) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.otpSecret = otpSecret;
        this.otpUrl = otpUrl;
    }

    public static Login of(Long userId, String accessSecret, String refreshSecret) {
        var otpSecret = generateOtpSecret();
        return new Login(
                Jwt.of(userId, ACCESS_TOKEN_VALIDITY, accessSecret),
                Jwt.of(userId, REFRESH_TOKEN_VALIDITY, refreshSecret),
                otpSecret, getOtpUrl(otpSecret)
        );
    }

    public static Login of(Long userId, String accessSecret, Jwt refreshToken) {
        var otpSecret = generateOtpSecret();
        return new Login(
                Jwt.of(userId,ACCESS_TOKEN_VALIDITY, accessSecret),
                refreshToken,
                otpSecret,
                getOtpUrl(otpSecret)
        );
    }

    private static String generateOtpSecret() {
        var uuid = UUID.randomUUID().toString();
        return BaseEncoding.base32().encode(uuid.getBytes(StandardCharsets.UTF_8));
    }

    private static String getOtpUrl(String otpSecret) {
        var appName = "My%20App";
        return String.format("otpauth://totp/%s:Secret?secret=%s&issuer=%s", appName, otpSecret, appName);
    }
}
