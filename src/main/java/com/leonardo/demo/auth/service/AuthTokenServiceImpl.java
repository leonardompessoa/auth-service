package com.leonardo.demo.auth.service;

import com.leonardo.demo.auth.config.JWTConfig;
import com.leonardo.demo.auth.model.TokenDetails;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.stream.Collectors;

@Service
@Slf4j
@AllArgsConstructor
public class AuthTokenServiceImpl implements AuthTokenService {

    private final JwtEncoder encoder;

    private final JWTConfig jwtConfig;

    @Override
    public TokenDetails generateToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expirationTime = now.plusMillis(jwtConfig.getExpirationInMillis());
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-service")
                .issuedAt(now)
                .expiresAt(expirationTime)
                .subject(authentication.getName())
                .claim("authorities", authorities)
                .build();
        String accessToken = this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return TokenDetails.builder()
                .username(authentication.getName())
                .accessToken(accessToken)
                .expirationTime(LocalDateTime.ofInstant(expirationTime, ZoneId.systemDefault())).build();
    }

}

