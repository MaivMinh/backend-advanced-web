package com.foolish.backend.service;

import com.foolish.backend.DTOs.UserDTO;
import com.foolish.backend.exceptions.ResourceNotFoundException;
import com.foolish.backend.mapper.UserMapper;
import com.foolish.backend.model.User;
import com.foolish.backend.repository.UserRepo;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@AllArgsConstructor
public class UserService {
  private final UserRepo userRepo;
  private final UserMapper userMapper;

  public UserDTO findByEmail(String email) {
    User user = userRepo.findByEmail(email);
    if (user == null)
      throw new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Email not found", Map.of("email", email));
    return userMapper.toDTO(user);
  }

  public User findUserByEmail(String email) {
    return userRepo.findByEmail(email);
  }

  public UserDTO save(User user) {
    return userMapper.toDTO(userRepo.save(user));
  }
}
