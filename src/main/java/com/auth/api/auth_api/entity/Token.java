package com.auth.api.auth_api.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name="tokens")
@Data
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true,nullable = false)
    private String token;

    @Column(nullable = false)
    private boolean expired=false;

    @ManyToOne
    @JoinColumn(name = "user_id",nullable = false)
    private User user;
}
