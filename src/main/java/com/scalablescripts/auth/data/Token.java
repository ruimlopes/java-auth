package com.scalablescripts.auth.data;

import java.time.LocalDateTime;

public record Token(String refreshToken, LocalDateTime issuedAt, LocalDateTime expiredAt) {}
