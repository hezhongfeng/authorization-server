package com.hezf.oauth.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.login.payload.LoginRequest;
import com.hezf.oauth.login.payload.LoginResult;
import com.hezf.oauth.security.JWTProvider;
import com.hezf.oauth.security.RefreshProvider;
import com.hezf.oauth.user.config.RespResult;
import com.hezf.oauth.user.entity.User;
import com.hezf.oauth.user.payload.CurrentResult;
import com.hezf.oauth.user.repo.UserRepo;
import com.hezf.oauth.user.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
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

  // private SecurityContextRepository securityContextRepository =
  // new HttpSessionSecurityContextRepository();

  // private final AuthenticationSuccessHandler successHandler =
  // new SavedRequestAwareAuthenticationSuccessHandler();


  @GetMapping("/login")
  public RespResult<Object> login() throws IOException, ServletException {
    // 这里还有一个问题，登录成功后如何继续进行授权或者返回成功？
    return new RespResult<Object>(200, "login成功", null);
  }

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

    if (user == null || !(new BCryptPasswordEncoder().matches(password, user.getPassword()))) {
      // 认证失败，返回错误信息
      return new RespResult<LoginResult>(201, "账号或密码错误", null);
    }

    // 获取完整用户信息
    CurrentResult currentUser = userService.getCurrentUser(login.getUsername());

    // // 权限列表
    // List<SimpleGrantedAuthority> permissions = currentUser.getPermissions().stream()
    // .map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());

    // // 设置空的上下文
    // SecurityContext context = SecurityContextHolder.createEmptyContext();

    // // 存储当前用户信息，这里最好存储 username,和authentication的 定义一致,不要存 userId
    // Authentication authentication =
    // new UsernamePasswordAuthenticationToken(username, null, permissions);

    // context.setAuthentication(authentication);

    // SecurityContextHolder.setContext(context);
    // securityContextRepository.saveContext(context, request, response);

    // 对于手动登录，需要运行 successHandler（SavedRequestAwareAuthenticationSuccessHandler），以便继续授权流程
    // successHandler.onAuthenticationSuccess(request, response, authentication);


    // // 获取完整用户信息
    // CurrentResult currentUser = userService.getCurrentUser(login.getUsername());

    // 使用 username 做 subject 和权限生成 JWT
    String token = JWTProvider.generateJWT(currentUser.getUsername(), currentUser.getPermissions());

    // 使用 username 做 subject生成 refreshJWT
    String refreshToken = RefreshProvider.generateRefreshJWT(user.getUsername());

    return new RespResult<LoginResult>(200, "登录成功",
        new LoginResult(token, refreshToken, currentUser.getUserId()));

    // 这里还有一个问题，登录成功后如何继续进行授权或者返回成功？
    // return new RespResult<LoginResult>(200, "登录成功", null);
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
