package com.hezf.oauth.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.hezf.oauth.admin.user.entity.Role;
import com.hezf.oauth.admin.user.entity.User;
import com.hezf.oauth.admin.user.repo.PermissionRepo;
import com.hezf.oauth.admin.user.repo.RoleRepo;
import com.hezf.oauth.admin.user.repo.UserRepo;
import jakarta.annotation.Resource;

@Service
public class CustomUserDetailsService implements UserDetailsService {
  @Resource
  private UserRepo userRepo;

  @Resource
  private RoleRepo roleRepo;

  @Resource
  private PermissionRepo permissionRepo;

  @Override
  @Transactional // 事务确保了，在查询user的时候是级联查询，会吧user的role和permission也查询出来
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    User user = userRepo.findByUsername(username);

    // 没有这个用户
    if (user == null) {
      throw new UsernameNotFoundException("用户不存在");
    }

    List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();

    Set<Role> roles = user.getRoles();

    for (Role role : roles) {
      role.getPermissions().forEach(permission -> {
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission.getKeyName());
        if (!authorities.contains(authority)) {
          authorities.add(authority);
        }
      });
    }

    return org.springframework.security.core.userdetails.User.builder().username(username)
        .password(user.getPassword()).authorities(authorities).build();
  }

}

