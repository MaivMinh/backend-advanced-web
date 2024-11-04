package com.foolish.backend.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;
  @Email(message = "Email must be valid")
  private String email;
  @Min(value = 6, message = "Password must be at least 8 characters")
  private String password;
  @Column(name = "full_name")
  private String fullName;

  @Column(name = "role")
  private String role;
}
