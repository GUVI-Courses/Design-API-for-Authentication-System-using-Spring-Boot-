package com.auth.api.auth_api.controller;
import com.auth.api.auth_api.entity.Token;
import com.auth.api.auth_api.repository.TokenRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api")
public class HomeController {

   private final TokenRepository tokenRepository;

   public HomeController(TokenRepository tokenRepository){
       this.tokenRepository = tokenRepository;
   }

   @GetMapping("/home")
   public ResponseEntity<String> homePage(@RequestHeader("Authorization") String token){
    if(token==null || !token.startsWith("Bearer ")){
        return ResponseEntity.status(401).body("Unauthorized! Token missing or invalid");
    }
    token = token.substring(7);
    Optional<Token> storedToken = tokenRepository.findByToken(token);

    if(storedToken.isEmpty() || storedToken.get().isExpired()){
        return  ResponseEntity.status(401).body("Unauthorized! Please login");
    }

    return ResponseEntity.ok("Welcome to HomePage");
   }
}
