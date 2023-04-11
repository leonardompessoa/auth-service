package com.leonardo.demo.auth.config;

import com.leonardo.demo.auth.filter.BasicToJWTAuthenticationFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

/*
*   This configuration class is my take on configuring the SecurityFilterChain without the WebSecurityConfigurerAdapter,
*   that is deprecated from Spring Security version 5.7 and on.
*
*   More information about this:
*   https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
* */
@Configuration
@EnableConfigurationProperties({JWTConfig.class})
public class AppWebSecurityConfiguration {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
                                    BasicToJWTAuthenticationFilter basicToJWTAuthenticationFilter) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .addFilterAfter(basicToJWTAuthenticationFilter, WebAsyncManagerIntegrationFilter.class)
                .authorizeRequests(urlRegistry ->
                        urlRegistry
                                .antMatchers(HttpMethod.POST, "/login").permitAll()
                                .anyRequest().authenticated()
                ).build();
    }

    /*
    * Left this piece of code commented to show whoever sees this,
    * that it is simple to add inMemory user management for test purposes
    *  NEVER USE THIS IN PRODUCTION
    *  .inMemoryAuthentication()
    *       .passwordEncoder(passwordEncoder)
    *       .withUser(User.builder().username("admin")
    *       .password("{noop}admin")
    *       .authorities("LOGIN"))
    8   .and()
    *
    * */
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity http, DataSource dataSource, PasswordEncoder passwordEncoder)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .jdbcAuthentication()
                    .dataSource(dataSource)
                    .passwordEncoder(passwordEncoder)
                .and()
                .build();
    }

    // This PasswordEncoder is using the delegatingPasswordEncoder,
    // so we can use more than one encoder, this is important in case you have
    @Bean
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
    AuthenticationConverter authenticationConverter() {
        return new BasicAuthenticationConverter();
    }

    @Bean
    BasicToJWTAuthenticationFilter basicToJWTAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationConverter authenticationConverter, JWTConfig jwtConfig) {
        return new BasicToJWTAuthenticationFilter(authenticationManager, authenticationConverter, jwtConfig);
    }

}