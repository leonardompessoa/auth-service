package com.leonardo.demo.auth.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

/*
*   This configuration class is my take on configuring the SecurityFilterChain without the WebSecurityConfigurerAdapter,
*   that is deprecated from Spring Security version 5.7 and on.
*
*   More information about this:
*   https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
* */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({JWTConfig.class})
public class AppWebSecurityConfiguration {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .httpBasic(withDefaults())
                .build();
    }

    @Bean
    UserDetailsManager userDetailsManager(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    // This PasswordEncoder is using the delegatingPasswordEncoder,
    // so we can use more than one encoder, this is important in case you have
    @Bean
    @SuppressWarnings("deprecation")
    PasswordEncoder passwordEncoder() {
        String idForEncode = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(idForEncode, new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("sha256", new StandardPasswordEncoder());

        return new DelegatingPasswordEncoder(idForEncode, encoders);
    }

    @Bean
    JwtDecoder jwtDecoder(JWTConfig jwtConfig) {
        return NimbusJwtDecoder.withPublicKey(jwtConfig.getPublicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder(JWTConfig jwtConfig) {
        JWK jwk = new RSAKey.Builder(jwtConfig.getPublicKey()).privateKey(jwtConfig.getPrivateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

}