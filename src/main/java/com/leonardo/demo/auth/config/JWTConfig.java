package com.leonardo.demo.auth.config;

import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@Getter
@AllArgsConstructor
@ToString
@EqualsAndHashCode
@ConfigurationProperties(prefix = "jwt.config")
@ConstructorBinding
public class JWTConfig {

    private final SignatureAlgorithm signatureAlgorithm;
    private final int expirationInMillis;
    private final String secretKey;

}


