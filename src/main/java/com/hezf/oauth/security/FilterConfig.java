package com.hezf.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
  @Autowired
  JWTFilter jwtFilter;

  @Bean
  public FilterRegistrationBean<JWTFilter> filterRegistrationBean() {
    // 注册过滤器(初始化过滤器)
    FilterRegistrationBean<JWTFilter> registrationBean = new FilterRegistrationBean<JWTFilter>();

    registrationBean.setFilter(jwtFilter);
    // 添加过滤的路径，凡是路径带 /api 的就进入过滤器，注意只能一个*号
    registrationBean.addUrlPatterns("/api/*");

    return registrationBean;
  }
}
