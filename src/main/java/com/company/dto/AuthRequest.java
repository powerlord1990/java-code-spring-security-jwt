package com.company.dto;

import lombok.Data;

import java.util.List;

@Data
public class AuthRequest {

    private String username;
    private String password;
    private List<String> roles;
}
