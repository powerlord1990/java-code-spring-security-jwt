package com.company.dto;

import lombok.Data;

import java.util.List;

@Data
public class ChangeRoleRequest {
    private String username;
    private List<String> newRole;
}
