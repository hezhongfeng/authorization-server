package com.hezf.oauth.admin.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.admin.login.payload.LoginRequest;
import com.hezf.oauth.admin.login.payload.LoginResult;
import com.hezf.oauth.admin.user.config.RespResult;
import com.hezf.oauth.admin.user.entity.User;
import com.hezf.oauth.admin.user.payload.CurrentResult;
import com.hezf.oauth.admin.user.repo.UserRepo;
import com.hezf.oauth.admin.user.service.UserService;
import com.hezf.oauth.security.JWTProvider;
import com.hezf.oauth.security.RefreshProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
@RestController
@RequestMapping("/api/v1")
public class LoginControllerV1 {

  @Autowired
  private UserRepo userRepo;

  @Autowired
  private UserService userService;

  /**
   * 登录
   * 
   * @throws ServletException
   * @throws IOException
   */
  @PostMapping("/login")
  public RespResult<LoginResult> login(@RequestBody LoginRequest login, HttpServletRequest request,
      HttpServletResponse response) throws IOException, ServletException {

    String username = login.getUsername();
    String password = login.getPassword();

    User user = userRepo.findByUsername(username);

    if (user == null || !(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(password, user.getPassword()))) {
      // 认证失败，返回错误信息
      return new RespResult<LoginResult>(201, "账号或密码错误", null);
    }

    // 获取完整用户信息
    CurrentResult currentUser = userService.getCurrentUser(login.getUsername());

    // 使用 username 做 subject 和权限生成 JWT
    String token = JWTProvider.generateJWT(currentUser.getUsername(), currentUser.getPermissions());

    // 使用 username 做 subject生成 refreshJWT
    String refreshToken = RefreshProvider.generateRefreshJWT(user.getUsername());

    return new RespResult<LoginResult>(200, "登录成功",
        new LoginResult(token, refreshToken, currentUser.getUserId()));
  }

  @GetMapping("/current")
  public RespResult<CurrentResult> getCurrentUseer() {
    // 拿到上一步设置的所有权限
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    String username = authentication.getPrincipal().toString();

    User user = userRepo.findByUsername(username);

    // 获取完整用户信息
    CurrentResult currentUser = userService.getCurrentUser(user.getUsername());

    return new RespResult<CurrentResult>(200, "", currentUser);
  }
}
