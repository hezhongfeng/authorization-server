package com.hezf.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DockerController {

  @Value("${DB_HOST}")
  private String dbHost;

  @RequestMapping("/")
  public String index() {
    return "Hello Index!" + dbHost;
  }
}
