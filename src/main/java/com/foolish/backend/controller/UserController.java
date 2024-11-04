package com.foolish.backend.controller;

import com.foolish.backend.DTOs.UserDTO;
import com.foolish.backend.response.ResponseData;
import com.foolish.backend.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping(value = "/api/v1/users")
public class UserController {
  private final UserService userService;

  @GetMapping("/profile")
  public ResponseEntity<ResponseData> getUser() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    UserDTO dto = userService.findByEmail(authentication.getName());
    return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Success", dto));
  }
}
