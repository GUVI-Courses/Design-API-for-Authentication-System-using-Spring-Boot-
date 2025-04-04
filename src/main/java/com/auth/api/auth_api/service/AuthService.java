package com.auth.api.auth_api.service;

import com.auth.api.auth_api.dto.LoginRequest;
import com.auth.api.auth_api.dto.LoginResponse;
import com.auth.api.auth_api.dto.RegisterRequest;
import com.auth.api.auth_api.entity.Token;
import com.auth.api.auth_api.entity.User;
import com.auth.api.auth_api.repository.TokenRepository;
import com.auth.api.auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(RegisterRequest request){
        if(userRepository.findByEmail(request.getEmail()).isPresent()){
            throw new RuntimeException(("Email already exists"));
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode((request.getPassword())));
        userRepository.save(user);

        return "User registered successfully";
    }

    public LoginResponse loginUser(LoginRequest request){
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(()->new RuntimeException("User not found"));

        if(!passwordEncoder.matches(request.getPassword(),user.getPassword())){
            throw new RuntimeException("Invalid Credentials");
        }

        String token = UUID.randomUUID().toString();
        Token authToken = new Token();
        authToken.setToken(token);
        authToken.setUser(user);
        tokenRepository.save(authToken);
        return new LoginResponse(token);
    }

    public String logoutUser(String token){
        Token storedToken = tokenRepository.findByToken(token)
                .orElseThrow(()->new RuntimeException("Invalid Token"));
        storedToken.setExpired(true);
        tokenRepository.save(storedToken);
        return "User logged out successfully";
    }

}
