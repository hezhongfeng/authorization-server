package com.hezf.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.hezf.oauth.authentication.federation.FederatedIdentityAuthenticationSuccessHandler;


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

  /**
   * 此方法配置的路由不会进入 Spring Security 机制进行验证
   */
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {

    String[] antMatchersAnonymous = {"/api/v1/login/**", "/api/v1/refresh-token/**", "/public/**",
        "/assets/**", "/webjars/**", "/login"};
    return web -> web.ignoring()
        // 放行所有OPTIONS请求
        .requestMatchers(HttpMethod.OPTIONS)
        // 开放一些路由
        .requestMatchers(antMatchersAnonymous);
  }

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    // 除了上面配置的那些录音，任意请求都需要已登录用户才可以访问
    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
        // 未登录
        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
        // 权限不足
        .accessDeniedHandler(new MyAccessDeniedHandler()));

    http.oauth2Login(oauth2Login -> oauth2Login.loginPage("/login")
        .successHandler(authenticationSuccessHandler()));

    return http.build();
  }

  private AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new FederatedIdentityAuthenticationSuccessHandler();
  }

  // // @formatter:off
	// @Bean
	// public UserDetailsService users() {
	// 	UserDetails user = User.withDefaultPasswordEncoder()
	// 			.username("user1")
	// 			.password("password")
	// 			.roles("USER")
	// 			.build();
	// 	return new InMemoryUserDetailsManager(user);
	// }
	// // @formatter:on

  // // 下面这俩好像没啥用啊
  // @Bean
  // public SessionRegistry sessionRegistry() {
  // return new SessionRegistryImpl();
  // }

  // @Bean
  // public HttpSessionEventPublisher httpSessionEventPublisher() {
  // return new HttpSessionEventPublisher();
  // }

}
