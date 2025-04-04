package com.auth.api.auth_api.controller;

import com.auth.api.auth_api.dto.LoginRequest;
import com.auth.api.auth_api.dto.LoginResponse;
import com.auth.api.auth_api.dto.RegisterRequest;
import com.auth.api.auth_api.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request){
        return ResponseEntity.ok(authService.loginUser(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String token){
        return ResponseEntity.ok(authService.logoutUser(token));
    }

}
