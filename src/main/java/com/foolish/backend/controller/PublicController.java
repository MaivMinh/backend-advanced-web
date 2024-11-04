package com.foolish.backend.controller;

import com.foolish.backend.response.ResponseData;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/public")
public class PublicController {

  @RequestMapping("/app-info")
  public ResponseEntity<ResponseData> getApplicationInfo() {
    return ResponseEntity.status(HttpStatus.OK).body(new ResponseData(HttpStatus.OK.value(), "Success", "Backend Advanced Web"));
  }
}
