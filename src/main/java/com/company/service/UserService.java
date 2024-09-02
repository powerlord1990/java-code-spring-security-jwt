package com.company.service;

import com.company.dto.AuthRequest;
import com.company.dto.ChangeRoleRequest;
import com.company.entity.User;
import com.company.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User registerUser(AuthRequest authRequest) {
        if (userRepository.findByUsername(authRequest.getUsername()).isPresent()) {
            throw new UsernameNotFoundException("User already exists");
        }
        User user = new User();
        user.setUsername(authRequest.getUsername());
        user.setPassword(passwordEncoder.encode(authRequest.getPassword()));
        ArrayList<String> roles = new ArrayList<>();
        roles.add("USER");
        user.setRoles(roles);

        User save = userRepository.save(user);
        log.info("User {} registered in successfully.", authRequest.getUsername());
        return save;
    }

    public void changeRole(ChangeRoleRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setRoles(request.getNewRole());
        userRepository.save(user);
        log.info("User {} role changed to {}.", request.getUsername(), request.getNewRole());
    }

}

