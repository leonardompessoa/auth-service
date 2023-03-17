package com.leonardo.demo.auth.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private BasicAuthenticationConverter authenticationConverter = new BasicAuthenticationConverter();

    public JwtUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        UsernamePasswordAuthenticationToken authRequest = authenticationConverter.convert(request);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    // Upon successful authentication, generate a token.
    // The 'auth' passed to successfulAuthentication() is the current authenticated user.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        long now = System.currentTimeMillis();
        String token = Jwts.builder()
                .setSubject(auth.getName())
                // Convert to list of strings.
                // This is important because it affects the way we get them back in the Gateway.
                .claim("authorities", auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + (24 * 60 * 60 * 1000)))  // in milliseconds
                .signWith(SignatureAlgorithm.HS512, "JwtSecretKey".getBytes())
                .compact();

        // Add token to header
        response.addHeader("Authorization", "Bearer " + token);
    }

}
