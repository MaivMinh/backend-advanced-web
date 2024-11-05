package com.foolish.backend.controller;

import com.foolish.backend.model.Owner;
import com.foolish.backend.repository.OwnerRepo;
import com.foolish.backend.response.ResponseData;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/public")
@AllArgsConstructor
public class PublicController {
  private final OwnerRepo ownerRepo;

  @RequestMapping("/app-info")
  public ResponseEntity<ResponseData> getApplicationInfo() {
    Owner owner = ownerRepo.findById(1);
    return ResponseEntity.status(HttpStatus.OK).body(new ResponseData(HttpStatus.OK.value(), "Success", "Application name: Backend Advanced Web, Owner name: " + owner.getName()));
  }
}
