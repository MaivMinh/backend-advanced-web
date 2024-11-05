package com.foolish.backend.controller;

import com.foolish.backend.DTOs.UserDTO;
import com.foolish.backend.exceptions.ResourceNotFoundException;
import com.foolish.backend.records.LoginRequest;
import com.foolish.backend.model.Role;
import com.foolish.backend.model.Token;
import com.foolish.backend.model.User;
import com.foolish.backend.records.LoginResponse;
import com.foolish.backend.response.ResponseData;
import com.foolish.backend.response.ResponseError;
import com.foolish.backend.service.RefreshTokenService;
import com.foolish.backend.service.TokenService;
import com.foolish.backend.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
@Slf4j
@RequestMapping(value = "/api/v1/auth")
public class AuthController {
  private final UserService userService;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final Environment env;
  private final TokenService tokenService;

  // API cung cấp chức năng đăng kí.
  @PostMapping(value = "/register")
  public ResponseEntity<ResponseData> register(@RequestBody @Valid User user) {
    String email = user.getEmail();
    try {
      UserDTO userDTO = userService.findByEmail(email);
    } catch (ResourceNotFoundException e) {
      user.setRole(Role.USER);
      user.setPassword(passwordEncoder.encode(user.getPassword()));
      UserDTO dto = userService.save(user);
      return ResponseEntity.ok(new ResponseData(HttpStatus.CREATED.value(), "User registered successfully", dto));
    }
    return ResponseEntity.status(200).body(new ResponseData(HttpStatus.BAD_REQUEST.value(), "User already exists", null));
  }

  // API cung cấp chức năng đăng nhập. Trả về JWT.
  @PostMapping(value = "/login")
  public ResponseEntity<ResponseData> login(@RequestBody LoginRequest data) {
    UserDTO dto = null;
    try {
      dto = userService.findByEmail(data.email());
    } catch (ResourceNotFoundException e) {
      // Nếu không tìm thấy User.
      return ResponseEntity.ok(new ResponseData(HttpStatus.NOT_FOUND.value(), "User not found", Map.of("email", data.email())));
    }

    String jwt = "";
    String refreshToken = "";
    Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(data.email(),  // Mục đích là tạo ra một token chưa authenticated để cho Provider có thể authenticate sau này.
            data.password());
    Authentication authenticated = authenticationManager.authenticate(authentication);

    if (authenticated != null && authenticated.isAuthenticated()) {
      if (null != env) {
        // Thực hiện việc tạo access-token và refresh-token.
        String email = authenticated.getName();
        refreshToken = RefreshTokenService.generateRefreshToken(email); // Mã hoá refresh-token dựa vào email.

        Token token = tokenService.findByContent(refreshToken); // Tìm xem refresh-token có tồn tại hay chưa.
        if (token == null) {
          token = new Token();
          token.setContent(refreshToken);
          token.setValidUntil(new Timestamp(new Date(new Date().getTime() + 2592000000L).getTime()));  // Có thời hạn 30 ngày.
          token.setEmail(authenticated.getName());
          token = tokenService.save(token);
        } else refreshToken = token.getContent();
        String secret = env.getProperty("SECRET_KEY");
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        jwt = Jwts.builder().setIssuer("Backend Advanced Web").setSubject("JWT Token")
                .claim("email", authenticated.getPrincipal().toString())
                .claim("roles", authenticated.getAuthorities().stream().map(
                        GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + 604800000L))
                .signWith(secretKey).compact();
      } else log.error("COULD NOT FIND ENVIRONMENT VARIABLE!");
    } else {
      log.error("USER ISN'T AUTHENTICATED!");
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ResponseData(HttpStatus.UNAUTHORIZED.value(), "Invalid user's credentials!", null));
    }
    ResponseCookie refreshCookie = ResponseCookie.from("refresh_token").value(refreshToken).httpOnly(true).path("/api/v1").maxAge(2592000000L).build();
    return ResponseEntity.ok().header("Set-Cookie", refreshCookie.toString()).body(new ResponseData(HttpStatus.OK.value(), "Login successfully", new LoginResponse("Bearer", jwt)));
  }

  // Tạo ra API để refresh access token.
  @GetMapping(value = "/refresh-token")
  public ResponseEntity<ResponseData> refreshToken(HttpServletRequest request) {
    StringBuilder refreshToken = new StringBuilder();
    Cookie[] cookies = request.getCookies();
    for (Cookie cookie : cookies) {
      if (cookie.getName().equals("refresh_token")) {
        // Tìm thấy được refresh_token.
        refreshToken.append(cookie.getValue());
        break;
      }
    }
    StringBuilder accessToken = new StringBuilder();
    String value = request.getHeader("Authorization");
    accessToken.append(value.substring(7));

    // Xác thực xem access-token đã hết hạn hay chưa.
    String secret = env.getProperty("SECRET_KEY");
    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    boolean isExpired = false;
    try {
       Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(accessToken.toString()).getBody();
    } catch (ExpiredJwtException e) {
      // Token thực sự hết hạn.
      log.error("Access token has truly expired");
      isExpired = true;
    } catch (RuntimeException e) {
      throw new RuntimeException("Validate JWT token failed!");
    }
    if (!isExpired) {
      return ResponseEntity.status(HttpStatus.OK).body(new ResponseError(HttpStatus.FORBIDDEN.value(), "Access token didn't expire!"));
    }
    Token token = tokenService.findByContent(refreshToken.toString());
    // Phải xét 2 trường hợp: token còn hạn và token hết hạn.

    // 1. Xét trường hợp token còn hạn.
    Timestamp current = new Timestamp(new Date().getTime());
    if (token != null && token.getValidUntil().getTime() > current.getTime()) {
      // Trả về cho Client một access-token mới.
      User user = userService.findUserByEmail(token.getEmail());
      String jwt = Jwts.builder().setIssuer("Backend Advanced Web").setSubject("JWT Token")
              .claim("email", token.getEmail())
              .claim("roles", user.getRole())
              .setIssuedAt(new Date())
              .setExpiration(new Date((new Date()).getTime() + 604800000L))
              .signWith(secretKey).compact();
      return ResponseEntity.ok(new ResponseData(HttpStatus.OK.value(), "Issued a new access token!", new LoginResponse("Bearer", jwt)));
    }
    // 2. Xét trường hợp là hết hạn, xoá refresh token dưới DB rồi sau đó trả về response yêu cầu Client đăng nhập lại.
    Token deletedToken = tokenService.deleteTokenByContent(refreshToken.toString());
    // deleted successfully.
    return ResponseEntity.status(HttpStatus.OK).body(new ResponseError(HttpStatus.UNAUTHORIZED.value(), "refresh token is expired!"));
  }
}
