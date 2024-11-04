package com.foolish.backend.filters;

import com.foolish.backend.records.ApplicationConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@AllArgsConstructor
public class JwtValidatorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    StringBuilder accessToken = new StringBuilder();
    // Extract Authorization header.
    String value = request.getHeader("Authorization");
    accessToken.append(value.substring(7));
    if (!accessToken.isEmpty()) {
      try {
        Environment env = getEnvironment();
        String secret = env.getProperty("SECRET_KEY", ApplicationConstant.SECRET_KEY);
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(accessToken.toString()).getBody();
        String email = claims.get("email").toString();
        String roles = String.valueOf(claims.get("roles"));
        Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, AuthorityUtils.commaSeparatedStringToAuthorityList(roles));
        //Thêm authenticated object vào SecurityContextHolder.
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } catch (ExpiredJwtException e) {
        throw new BadCredentialsException("Expired JWT token");
      } catch (SignatureException e) {
        throw new BadCredentialsException("Invalid signature!", e);
      } catch (RuntimeException e) {
        throw new RuntimeException("Validate JWT token failed");
      }
    } else throw new BadCredentialsException("Token not found!");
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return false;
  }
}
