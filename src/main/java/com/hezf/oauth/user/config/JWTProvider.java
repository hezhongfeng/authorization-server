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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTProvider {
	
	private static final Logger logger = LoggerFactory.getLogger(JWTProvider.class);

	private static String jwtSecret;

	private static int jwtExpirationInMs;

	@Value("${jwt.secret}")
	public void setJwtSecret(String secret) {
		jwtSecret = secret;
	}

	// @Value("${jwt.secret}")
	// public JWTProvider( String secret) {
	// // byte[] decodedKey = Base64.getDecoder().decode(secret);
	// // jwtSecret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	// // this.jwtSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
	// // jwtSecret = Keys.secretKeyFor(SignatureAlgorithm.HS256);

	// }

	// public JWTProvider(@Value("${jwt.secret}") String secret) {
	// this.jwtSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
	// }



	@Value("${jwt.expire}")
	public void setJwtExpirationInMs(int expire) {
		jwtExpirationInMs = expire;
	}

	// 根据subject生成token
	public static String generateJWT(String subject, List<String> permissions) {

		long currentTimeMillis = System.currentTimeMillis();
		Date expirationDate = new Date(currentTimeMillis + jwtExpirationInMs * 1000);

		return Jwts.builder().setSubject(subject).claim("permissions", String.join(",", permissions))
				.signWith(SignatureAlgorithm.HS256, jwtSecret).setIssuedAt(new Date()).setExpiration(expirationDate).compact();
	}

	public static Authentication getAuthentication(String token) {
		Claims claims =
				Jwts.parserBuilder().setSigningKey(jwtSecret).build().parseClaimsJws(token).getBody();
		// 从jwt获取用户权限列
		// 注意这里不需要从数据库查询，否则会造成性能浪费，只需要在封路成功颁发jwt的时候查询一次就可以了
		// 关于这部分的讨论：https://stackoverflow.com/questions/51507978/is-it-more-efficient-to-store-the-permissions-of-the-user-in-an-jwt-claim-or-to
		String permissionString = (String) claims.get("permissions");

		List<SimpleGrantedAuthority> authorities =
				permissionString.isBlank() ? new ArrayList<SimpleGrantedAuthority>()
						: Arrays.stream(permissionString.split(",")).map(SimpleGrantedAuthority::new)
								.collect(Collectors.toList());

		// 获取用户Id
		Long userId = Long.valueOf(claims.getSubject());

		return new UsernamePasswordAuthenticationToken(userId, null, authorities);
	}

	public static boolean validateToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(jwtSecret).build().parseClaimsJws(authToken);
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
