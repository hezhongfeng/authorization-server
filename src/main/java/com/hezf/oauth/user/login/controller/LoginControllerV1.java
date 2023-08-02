package com.hezf.oauth.user.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.user.config.RespResult;
import com.hezf.oauth.user.entity.User;
import com.hezf.oauth.user.login.payload.LoginRequest;
import com.hezf.oauth.user.login.payload.LoginResultNew;
import com.hezf.oauth.user.payload.CurrentResult;
import com.hezf.oauth.user.repo.UserRepo;
import com.hezf.oauth.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/v1")
public class LoginControllerV1 {

  @Autowired
  private UserRepo userRepo;

  @Autowired
  private UserService userService;

  private static final Logger LOGGER = LoggerFactory.getLogger(LoginControllerV1.class);

  /**
   * 登录
   */
  @PostMapping("/login")
  public RespResult<LoginResultNew> login(@RequestBody LoginRequest login) {

    String username = login.getUsername();
    String password = login.getPassword();

    User user = userRepo.findByUsername(username);

    if (user == null || !(new BCryptPasswordEncoder().matches(password, user.getPassword()))) {
      // 认证失败，返回错误信息
      return new RespResult<LoginResultNew>(201, "帐户或密码错误", null);
    }

    // 获取完整用户信息
    CurrentResult currentUser = userService.getCurrentUser(login.getUsername());

    // 使用用户 Id 做 subject和使用权限生成token
    String token =
        "JWTProvider.generateToken(Long.toString(currentUser.getUserId()),currentUser.getPermissions())";

    String refreshTokenNew = "RefreshProvider.generateRefresh(Long.toString(user.getId()))";

    return new RespResult<LoginResultNew>(200, "登录成功",
        new LoginResultNew(token, refreshTokenNew, currentUser.getUserId()));
  }

  @GetMapping("/current")
  public RespResult<CurrentResult> getCurrentUseer() {
    // 拿到上一步设置的所有权限
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    Long userId = Long.parseLong(authentication.getPrincipal().toString());

    User user = userRepo.findById(userId).get();

    // 获取完整用户信息
    CurrentResult currentUser = userService.getCurrentUser(user.getUsername());

    return new RespResult<CurrentResult>(200, "", currentUser);
  }
}
