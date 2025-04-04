package com.auth.api.auth_api.config;

import com.auth.api.auth_api.repository.TokenRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    private final TokenRepository tokenRepository;
    private final TokenAuthenticationFilter tokenAuthenticationFilter;
    public SecurityConfig(TokenRepository tokenRepository,TokenAuthenticationFilter tokenAuthenticationFilter){
        this.tokenRepository = tokenRepository;
        this.tokenAuthenticationFilter = tokenAuthenticationFilter;

    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return  authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/api/auth/register","/api/auth/login").permitAll()
                        .requestMatchers("/api/home").authenticated()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout->logout.logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            String authHeader = request.getHeader("Authorization");
                            if(authHeader!=null && authHeader.startsWith("Bearer ")){
                                String token = authHeader.substring(7);
                                tokenRepository.findByToken(token).ifPresent(storedToken->{
                                    storedToken.setExpired(true);
                                    tokenRepository.save(storedToken);
                                });
                            }
                            response.setStatus(200);
                            response.getWriter().write("User logged out successfully");
                        })
                        )
                .exceptionHandling(exception->
                    exception.authenticationEntryPoint((request, response, authException) -> {
                        response.sendError(403,"Access Denied");
                    }));

                return http.build();

    }

}
