package com.leonardo.demo.auth.config;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Getter
@AllArgsConstructor
@ToString
@EqualsAndHashCode
@ConfigurationProperties(prefix = "jwt")
@ConstructorBinding
public class JWTConfig {

    private final int expirationInMillis;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

}


