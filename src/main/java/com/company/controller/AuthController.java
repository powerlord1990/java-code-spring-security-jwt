package com.company.controller;

import com.company.dto.AuthRequest;
import com.company.dto.AuthResponse;
import com.company.dto.ChangeRoleRequest;
import com.company.entity.User;
import com.company.security.utils.JwtUtil;
import com.company.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@RequestBody AuthRequest authRequest) {
        return ResponseEntity.ok(userService.registerUser(authRequest));
    }


    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody AuthRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
            if (authentication != null && authentication.isAuthenticated()) {
                log.info("User {} logged in successfully.", authRequest.getUsername());
            }
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String jwt = JwtUtil.generateToken(userDetails);

            return ResponseEntity.ok(new AuthResponse(jwt));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody String refreshToken) {
        String newToken = null;
        try {
            if (JwtUtil.validateToken(refreshToken)) {
                newToken = JwtUtil.refreshToken(refreshToken);
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
        return ResponseEntity.ok(newToken);
    }
    @PostMapping("/change-role")
    public ResponseEntity<Void> changeRole(@RequestBody ChangeRoleRequest request){
        userService.changeRole(request);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
