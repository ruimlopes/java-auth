package com.scalablescripts.auth.service;

import dev.samstevens.totp.secret.DefaultSecretGenerator;
import lombok.Getter;

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

    public static Login of(Long userId, String accessSecret, String refreshSecret, Boolean generateOtp) {
        String otpSecret = null;
        String otpUrl = null;

        if (generateOtp) {
            otpSecret = generateOtpSecret();
            otpUrl = getOtpUrl(otpSecret);
        }

        return new Login(
                Jwt.of(userId, ACCESS_TOKEN_VALIDITY, accessSecret),
                Jwt.of(userId, REFRESH_TOKEN_VALIDITY, refreshSecret),
                otpSecret,
                otpUrl
        );
    }

    public static Login of(Long userId, String accessSecret, Jwt refreshToken, Boolean generateOtp) {
        String otpSecret = null;
        String otpUrl = null;

        if (generateOtp) {
            otpSecret = generateOtpSecret();
            otpUrl = getOtpUrl(otpSecret);
        }

        return new Login(
                Jwt.of(userId,ACCESS_TOKEN_VALIDITY, accessSecret),
                refreshToken,
                otpSecret,
                otpUrl
        );
    }

    private static String generateOtpSecret() {
        return new DefaultSecretGenerator().generate();
    }

    private static String getOtpUrl(String otpSecret) {
        var appName = "My%20App";
        return String.format("otpauth://totp/%s:Secret?secret=%s&issuer=%s", appName, otpSecret, appName);
    }
}
