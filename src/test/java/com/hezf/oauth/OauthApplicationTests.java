package com.hezf.oauth;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.annotation.Rollback;
import com.hezf.oauth.user.service.UserService;

@SpringBootTest
class OauthApplicationTests {

	@Autowired
	private UserService userService;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	void contextLoads() {
		if (new BCryptPasswordEncoder().matches("secret",
				"$2a$10$kYEqs8S4mwUSP7ures8ZSuqeng0HI28moJ7htsXcxr3U3QtL31FAC")) {

			System.out.println("验证过");

		} else {
			System.out.println("失败了");
		}


		// $2a$10$9pZ9l2xSWcpmNCas2Gsf6eOsswpQ/rVSCGyxdVKptLKq4YsH7UCfi

	}

	@Test
	@Rollback(false)
	void initUsers() {
		// 初始化用户
		userService.initAllUsers();
	}


	@Test
	@Rollback(false)
	void addClient() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientName("测试form").clientId("form-client")
				// 注意存完的时候是{noop}secret，但是验证过之后就变为了{bcrypt}$2a$10$5igAFJvkf0wg.f5ml2bBgOO.13LmzgOhWwiwZZtTKCjkX0f3wiwJ2
				// {bcrypt}$2a$10$kYEqs8S4mwUSP7ures8ZSuqeng0HI28moJ7htsXcxr3U3QtL31FAC
				// 去除了{bcrypt}之后可以正常验证 new
				// BCryptPasswordEncoder().matches("secret","$2a$10$kYEqs8S4mwUSP7ures8ZSuqeng0HI28moJ7htsXcxr3U3QtL31FAC")
				.clientSecret("secret").clientIdIssuedAt(Instant.now())
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out").scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE).scope("message.read").scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();

		registeredClientRepository.save(registeredClient);

	}
}
