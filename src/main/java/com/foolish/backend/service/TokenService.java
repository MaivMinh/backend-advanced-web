package com.foolish.backend.service;

import com.foolish.backend.model.Token;
import com.foolish.backend.repository.TokenRepo;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class TokenService {
  private final TokenRepo tokenRepo;

  public Token findByContent(String token) {
    return tokenRepo.findByContent(token);
  }
  public Token save(Token token) {
    return tokenRepo.save(token);
  }

  public Token deleteTokenByContent(String content) {
    return tokenRepo.deleteTokenByContent(content);
  }
}
