package com.foolish.backend.security;

import com.foolish.backend.exceptions.ResourceNotFoundException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor
@Configuration
@Slf4j
public class ProdUsernamePwdAuthenticationProvider implements AuthenticationProvider {
  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    // Hàm thực hiện xác thực {username, password} của User khi thực hiện Sign-In.
    String email = authentication.getName();
    String rawPassword = authentication.getCredentials().toString();
    try {
      UserDetails userDetails = userDetailsService.loadUserByUsername(email);
      boolean isMatched = passwordEncoder.matches(rawPassword, userDetails.getPassword());
      if (isMatched) {
        return new UsernamePasswordAuthenticationToken(email, userDetails.getPassword(), userDetails.getAuthorities());
      } else {
        log.info("PASSWORD DOESN'T MATCH!");
        return new UsernamePasswordAuthenticationToken(email, rawPassword);
      }
    } catch (ResourceNotFoundException e1) {
      log.error(e1.getMessage());
      throw e1;
    } catch (Exception e) {
      log.error("Failed to authenticate user with email: {}", email, e);
      throw new AuthenticationException("Authentication failed!") {
      };
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
