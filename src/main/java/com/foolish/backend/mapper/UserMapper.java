package com.foolish.backend.mapper;

import com.foolish.backend.DTOs.UserDTO;
import com.foolish.backend.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface UserMapper {
  UserMapper INSTANCE = Mappers.getMapper(UserMapper.class );

  @Mapping(source = "id", target = "id")
  @Mapping(source = "email", target = "email")
  @Mapping(source = "role", target = "role")
  UserDTO toDTO(User user);
}
