package com.hezf.oauth.user.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;

@Component
public class RefreshProvider {
	private static final Logger logger = LoggerFactory.getLogger(JWTProvider.class);

	private static Key refreshSecret;

	@Value("${refresh.secret}")
	public void setRefreshSecret(String secret) {
		byte[] decodedKey = Base64.getDecoder().decode(secret);
		refreshSecret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	}

	private static int jwtExpirationInMs;

	@Value("${refresh.expire}")
	public void setRefreshExpirationInMs(int expire) {
		jwtExpirationInMs = expire;
	}

	// 根据subject生成token
	public static String generateRefresh(String subject) {

		long currentTimeMillis = System.currentTimeMillis();
		Date expirationDate = new Date(currentTimeMillis + jwtExpirationInMs * 1000);

		return Jwts.builder().setSubject(subject).signWith(refreshSecret, SignatureAlgorithm.HS256)
				.setIssuedAt(new Date()).setExpiration(expirationDate).compact();
	}

	public static Authentication getAuthentication(String token) {
		Claims claims =
				Jwts.parserBuilder().setSigningKey(refreshSecret).build().parseClaimsJws(token).getBody();


		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();

		// 获取用户Id
		Long userId = Long.valueOf(claims.getSubject());

		return new UsernamePasswordAuthenticationToken(userId, null, authorities);
	}

	public static boolean validateToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(refreshSecret).build().parse(authToken);
			return true;
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}
		return false;
	}
}
