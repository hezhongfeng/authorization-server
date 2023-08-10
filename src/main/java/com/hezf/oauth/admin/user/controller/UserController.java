package com.hezf.oauth.admin.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.admin.user.config.RespResult;
import com.hezf.oauth.admin.user.entity.User;
import com.hezf.oauth.admin.user.payload.UpdatePassword;
import com.hezf.oauth.admin.user.payload.UpdateUserSelfDto;
import com.hezf.oauth.admin.user.repo.UserRepo;
import com.hezf.oauth.admin.user.service.UserService;


@RestController
@RequestMapping("/api/v1/users")
class UserController {

  @Autowired
  private UserRepo userRepo;

  @Autowired
  private UserService userService;

  @PutMapping("/{id}")
  public RespResult<Object> UpdateUser(@RequestBody @Validated UpdateUserSelfDto updateUser,
      @PathVariable("id") Long id) {

    // 首先检查是否和当前用户匹配
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.parseLong(authentication.getPrincipal().toString());
    User contentUser = userRepo.findById(userId).get();

    if (contentUser.getId() != id) {
      return new RespResult<Object>(201, "权限错误", null);
    }

    userService.updateUserBase(updateUser, id);

    return new RespResult<Object>(200, "", null);
  }

  @PutMapping("/{id}/password")
  public RespResult<String> UpdateUserPassword(
      @RequestBody @Validated UpdatePassword updatePassword, @PathVariable("id") Long id) {
    // 首先检查是否和当前用户匹配
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Long userId = Long.parseLong(authentication.getPrincipal().toString());
    User contentUser = userRepo.findById(userId).get();

    if (contentUser.getId() != id) {
      return new RespResult<String>(201, "权限错误", null);
    }

    User user = userRepo.findById(id).get();

    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    if (!bCryptPasswordEncoder.matches(updatePassword.getPassword(), user.getPassword())) {
      return new RespResult<String>(201, "原密码错误", null);
    }

    userService.updateUserPassword(id, updatePassword.getNewPassword());

    return new RespResult<String>(200, "", null);
  }

}
