package com.leonardo.demo.auth.model;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Builder
@Getter

public class TokenDetails {

    private final String username;
    private final String accessToken;
    private final LocalDateTime expirationTime;

}
