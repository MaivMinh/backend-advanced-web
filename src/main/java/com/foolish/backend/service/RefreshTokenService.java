package com.foolish.backend.service;

import java.util.Base64;

public class RefreshTokenService {
  private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding(); // Encoder Base64 để chuyển đổi thành chuỗi

  public static String generateRefreshToken(String username) {
    return base64Encoder.encodeToString(username.getBytes());
  }
}
