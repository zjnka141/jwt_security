package com.codegym.jwt_security.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Table(name="user")
@Data
@JsonIgnoreProperties(value = "role")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    int id;
    @Column(nullable = false, unique = true)
    String username;
    @NotNull
    String password;
    String role;
}
