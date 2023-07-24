package com.hezf.oauth;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DockerController {

  @RequestMapping("/")
  public String index() {
    return "Hello Index!";
  }
}
