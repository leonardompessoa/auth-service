package com.leonardo.demo.auth.model;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter

public class UserRequest {

    private String username;
    private String password;
    private String roles;

}
