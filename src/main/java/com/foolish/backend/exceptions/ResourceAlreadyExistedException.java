package com.foolish.backend.exceptions;

import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.util.Map;

@NoArgsConstructor
public class ResourceAlreadyExistedException extends AbstractException{
  public ResourceAlreadyExistedException(HttpStatus status, String message, Map<String, String> details) {
    super(status, message, details);
  }
}

