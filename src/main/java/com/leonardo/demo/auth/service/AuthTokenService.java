package com.leonardo.demo.auth.service;

import com.leonardo.demo.auth.model.TokenDetails;
import org.springframework.security.core.Authentication;

public interface AuthTokenService {
    TokenDetails generateToken(Authentication authentication);
}
