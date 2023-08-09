package com.hezf.oauth.user.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class JWTFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(JWTFilter.class);

  private Set<String> skipUrls =
      new HashSet<>(Arrays.asList("/api/v1/login", "/api/v1/refresh-token"));

  private AntPathMatcher pathMatcher = new AntPathMatcher();

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    // 这部分出错后，直接返回401，不再走后面的filter
    try {
      // 从请求头中获取jwt
      String jwt = getJwtFromRequest(request);

      // 校验 jwt 是否有效，包含了过期的验证
      if (StringUtils.hasText(jwt) && JWTProvider.validateToken(jwt)) {

        // 通过 jwt 获取认证信息
        Authentication authentication = JWTProvider.getAuthentication(jwt);

        // 将认证信息存入 Security 上下文中，可以取出来使用
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception ex) {
      LOGGER.error("Could not set user authentication in security context", ex);
    }

    filterChain.doFilter(request, response);
  }

  // 设置不需要过滤的 URL
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return skipUrls.stream().anyMatch(p -> pathMatcher.match(p, request.getRequestURI()));
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7, bearerToken.length());
    }
    return null;
  }
}
