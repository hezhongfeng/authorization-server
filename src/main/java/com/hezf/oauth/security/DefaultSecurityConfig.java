package com.hezf.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import com.hezf.oauth.authentication.federation.FederatedIdentityAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class DefaultSecurityConfig {

  // @formatter:off
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE+1)
  public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {

    String[] antMatchersAnonymous = {"/api/v1/login/**", "/api/v1/refresh-token/**"};

    http.securityMatcher("/api/**");

    http.authorizeHttpRequests(authorize -> {
        authorize.requestMatchers(antMatchersAnonymous).permitAll().anyRequest().authenticated();
    });

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
    // 未登录
    .authenticationEntryPoint(new MyAuthenticationEntryPoint())
    // 权限不足
    .accessDeniedHandler(new MyAccessDeniedHandler()));

    // 确保在登出的时候，可以访问到 jwt 相关信息
    // `LogoutFilter` 排在 `UsernamePasswordAuthenticationFilter` 的前面
    http.addFilterBefore(new JWTFilter(), LogoutFilter.class);

    http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.csrf(csrf -> csrf.disable());
    http.httpBasic(httpBasic-> httpBasic.disable());      
    http.formLogin(formLogin-> formLogin.disable());

    return http.build();
  }
  // @formatter:on

  // @formatter:off
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE+2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
  
      String[] antMatchersAnonymous = {"/public/**", "/assets/**", "/webjars/**", "/login"};
  
      http
        .authorizeHttpRequests(authorize -> authorize
           // 开放一些路由
          .requestMatchers(antMatchersAnonymous).permitAll()
          // 放行所有OPTIONS请求
          .requestMatchers(HttpMethod.OPTIONS).permitAll()
          //  除了上面的配置，任意请求都需要已登录用户才可以访问
          .anyRequest().authenticated());

      // 允许 API 接口不经过 csrf 保护
      // http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));

      // 正常的登录和 oauth2 授权
      http.formLogin(formLogin -> formLogin.loginPage("/login"))
          .oauth2Login(oauth2Login -> oauth2Login.loginPage("/login").successHandler(authenticationSuccessHandler())); // 登录成功后继续之前的授权行为;
  
      return http.build();
    }
    // @formatter:on

  private AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new FederatedIdentityAuthenticationSuccessHandler();
  }

  // @formatter:off
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	// @formatter:on
}
