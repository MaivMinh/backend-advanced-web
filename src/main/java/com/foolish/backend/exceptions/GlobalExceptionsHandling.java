package com.foolish.backend.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice(annotations = RestController.class)
@Order(1)
public class GlobalExceptionsHandling {

  @ExceptionHandler({AbstractException.class})
  public ResponseEntity<ExceptionResponse> handleAbstractionExceptions(AbstractException exception) {
    return ResponseEntity.status(exception.getStatus())
            .body(new ExceptionResponse(exception.getMessage(), exception.getDetails()));
  }

  @ExceptionHandler({ExpiredJwtException.class})
  public ResponseEntity<ExceptionResponse> handleExpiredJwtException(ExpiredJwtException exception) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ExceptionResponse(exception.getMessage(), null));
  }

  @ExceptionHandler({SignatureException.class})
  public ResponseEntity<ExceptionResponse> handleSignatureException(SignatureException exception) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ExceptionResponse(exception.getMessage(), Map.of("cause", exception.getCause().toString())));
  }

  @ExceptionHandler({RuntimeException.class})
  public ResponseEntity<ExceptionResponse> handleRuntimeException(RuntimeException exception) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ExceptionResponse(exception.getMessage(), null));
  }
}
