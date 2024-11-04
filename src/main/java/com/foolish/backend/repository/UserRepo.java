package com.foolish.backend.repository;

import com.foolish.backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Integer> {
  User findByEmail(String email);
}
