package com.auth.api.auth_api.config;

import com.auth.api.auth_api.entity.Token;
import com.auth.api.auth_api.repository.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    private final TokenRepository tokenRepository;

    public TokenAuthenticationFilter(TokenRepository tokenRepository){
        this.tokenRepository = tokenRepository;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
        String requestURI = request.getRequestURI();
        if(requestURI.startsWith("/api/auth/login") || requestURI.startsWith("/api/auth/register")){
            filterChain.doFilter(request,response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if(authHeader!=null && authHeader.startsWith("Bearer ")){
            String token = authHeader.substring(7);
            Optional<Token> storedToken = tokenRepository.findByToken(token);

            if(storedToken.isPresent()){
                Token tokenEntity = storedToken.get();
                if(tokenEntity.isExpired()){
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Token is Expired! please login");
                    return;
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(tokenEntity,null,Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request,response);
    }
}
