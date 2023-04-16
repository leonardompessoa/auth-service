package com.leonardo.demo.auth.controller;

import com.leonardo.demo.auth.model.TokenDetails;
import com.leonardo.demo.auth.service.AuthTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class AuthenticationController {

    private AuthTokenService authTokenService;

    @PostMapping("/token")
    public TokenDetails token(Authentication authentication) {
        return authTokenService.generateToken(authentication);
    }

}
