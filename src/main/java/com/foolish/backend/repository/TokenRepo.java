package com.foolish.backend.repository;

import com.foolish.backend.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepo extends JpaRepository<Token, Integer> {
  Token findByContent(String content);
  Token deleteTokenByContent(String content);
}
