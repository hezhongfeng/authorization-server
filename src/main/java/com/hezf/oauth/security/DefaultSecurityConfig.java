package com.hezf.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.hezf.oauth.authentication.federation.FederatedIdentityAuthenticationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

  // @formatter:off
  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    String[] antMatchersAnonymous = {"/api/*", "/public/**", "/assets/**", "/webjars/**", "/login"};

    // http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));

    http
      .authorizeHttpRequests(authorize -> authorize
         // 开放一些路由
        .requestMatchers(antMatchersAnonymous).permitAll()
        // 放行所有OPTIONS请求
        .requestMatchers(HttpMethod.OPTIONS).permitAll()
        //  除了上面的配置，任意请求都需要已登录用户才可以访问
        .anyRequest().authenticated())
        // .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
        .csrf(csrf -> csrf.disable())
        .formLogin(formLogin -> formLogin.loginPage("/login"))
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
