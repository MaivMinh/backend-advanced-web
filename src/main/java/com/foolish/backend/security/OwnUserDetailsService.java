package com.foolish.backend.security;

import com.foolish.backend.exceptions.ResourceNotFoundException;
import com.foolish.backend.model.User;
import com.foolish.backend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class OwnUserDetailsService implements UserDetailsService {
  private final UserService userService;

  public OwnUserDetailsService(UserService userService) {
    this.userService = userService;
  }

  @Override
  public UserDetails loadUserByUsername(String email) {
    User user = userService.findUserByEmail(email);
    if (user != null && user.getId() > 0) {
      List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
      return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }
    throw new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Email not found", Map.of("email", email));
  }
}
