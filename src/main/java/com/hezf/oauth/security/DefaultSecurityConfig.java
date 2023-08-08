package com.hezf.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

// import static com.example.rbac.security.CustomDsl.customDsl;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

  /**
   * 此方法配置的路由不会进入 Spring Security 机制进行验证
   */
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {

    String[] antMatchersAnonymous = {"/api/v1/login/**", "/api/v1/refresh-token/**", "/public/**"};
    return web -> web.ignoring()
        // 放行所有OPTIONS请求
        .requestMatchers(HttpMethod.OPTIONS)
        // 开放一些路由
        .requestMatchers(antMatchersAnonymous);
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    // 任意请求都需要已登录用户才可以访问
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
        // 未登录
        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
        // 权限不足
        .accessDeniedHandler(new MyAccessDeniedHandler()));


    // 关闭 CSRF
    http.httpBasic().disable()
        // 前后端分离不需要csrf保护
        .csrf().disable()
        // 禁用默认登录页
        .formLogin().disable()
        // 禁用默认登出页
        .logout().disable();

    // 不创建会话
    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    // 这块原来为啥不写在这里呢？好像是因为SecurityFilterChain的新写法给的例子
    // http.addFilterBefore(new JWTFilter(), LogoutFilter.class);

    // 通过 CustomDsl 来配置自定义的过滤器
    // http.apply(customDsl());

    return http.build();
  }
}
