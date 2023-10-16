# authorization-server

authorization-server

1. 实现 OAuth2.1 草案的授权方式（认证码包括 Refresh Token、oidc、PKCE 认证 ）
2. client 管理，主要是密码和 redirecturl、logouturl 的管理
3. 用户系统管理，有角色和权限的区分，有管理用户和普通用户
4. 可以统一退出（client 退出后，authorization-server 端也退出，这个可选）
5. 有 client 的 demo（springboot、nestjs，也有前端，可以进行修改用户信息等操作）
6. 支持对 consent 的过期管理（比如说，同意一次一个月内有效这种）

## 认证过程

### client 启动

client 会向 server 发送请求 openid 配置的请求，两个一样的请求： `HTTP GET http://localhost:9000/.well-known/openid-configuration`

然后 server 回复：

```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
  "device_authorization_endpoint": "http://localhost:9000/oauth2/device_authorization",
  "token_endpoint": "http://localhost:9000/oauth2/token",
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  ],
  "jwks_uri": "http://localhost:9000/oauth2/jwks",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "end_session_endpoint": "http://localhost:9000/connect/logout",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "revocation_endpoint": "http://localhost:9000/oauth2/revoke",
  "revocation_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  ],
  "introspection_endpoint": "http://localhost:9000/oauth2/introspect",
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  ],
  "code_challenge_methods_supported": ["S256"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid"]
}
```

## oidc 认证

访问 client 的根目录 `http://localhost:8080/`

302 `http://localhost:8080/oauth2/authorization/messaging-client-oidc`

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20profile&state=W2rzdFZDm6smyMbFGtmHWLUYqGv_vHtoEnjFnKwPzQI%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=syQCDUpwdQyw65SOSk0aEDD7uUtws4yVpKaQ3i3EblM`

302 `http://localhost:9000/login` 返回登录页面，前端展示页面

输入用户名、密码提交登录`POST /login`

继续之前的请求

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20profile&state=W2rzdFZDm6smyMbFGtmHWLUYqGv_vHtoEnjFnKwPzQI%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=syQCDUpwdQyw65SOSk0aEDD7uUtws4yVpKaQ3i3EblM&continue`

因为未授权，302 `http://localhost:9000/oauth2/consent?scope=openid%20profile&client_id=messaging-client&state=xEj96Penx2THjBoAnL4HYjuSiP0niVFTmNsSVmYPjB8%3D` 返回前端页面，这个是授权页面

选择 scope 之后 提交`POST /oauth2/authorize`，以下为数据：

```form data
_csrf: IDT1ahoTSlfwfu8iERXOf_ZMO0CLHFHulNt_L19g17_nhI2nEwLADCpyezPdGtdHczj6SJN6FnjpeWXDrOIdTDxZsd7Stb6T
client_id: messaging-client
state: Vb9pnRRY4uER1STpREzqhCyzD_CT0gNE_YHBjdemap4=
scope: profile
```

302 `http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc?code=UK6l2_-p-1VjjgOr8lRahDmKpg8MvC4GrY0zFk4txmRVlS9zERuwYC2rHtWUtSEQACTsRIit9uWLYrJgvb-USs6OAp7jKoVhqnjAsUU4AmUemKChSiq9wiD9Vk-pLITY&state=djXuffVHeaqHQrn9M-f5XHP8e3BiVo7ARhn4jiYW0eM%3D`

302 `http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc?error`

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20profile&state=k4o4H4IBl6CHn_s0k1dN8a-jXVMBntQxEyZAiF0NF-A%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=ravL1Z7yyheAX-8okPBFsuCkvtvpRehsBR3fqyVcqQg`

302 到 `http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc?code=8iJ6r5v-heZ8Y6Y8F4MdDLX2FO54mJbN-dehuN6kNPZ1fL11IgsOmChQYT5yDKpPzTmJEWJz-UjBKzXlk87jRkqxblfXzj-EoBXTHFGnk8vMfj2kAhtwxMr-VllYb_3p&state=k4o4H4IBl6CHn_s0k1dN8a-jXVMBntQxEyZAiF0NF-A%3D`

这时候 client 会向 server `HTTP POST http://localhost:9000/oauth2/token`,body 是：

```json
{
  "grant_type": "authorization_code",
  "code": "8iJ6r5v-heZ8Y6Y8F4MdDLX2FO54mJbN-dehuN6kNPZ1fL11IgsOmChQYT5yDKpPzTmJEWJz-UjBKzXlk87jRkqxblfXzj-EoBXTHFGnk8vMfj2kAhtwxMr-VllYb_3p",
  "redirect_uri": "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc"
}
```

server 回复的是：

```json
{
  "access_token": "eyJraWQiOiIwOWRmNzRmZi0wMzBhLTRkYzMtYmYxZi05ODAxMDlhYjRkMmQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2OTcxNzg4MjUsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjk3MTc5MTI1LCJpYXQiOjE2OTcxNzg4MjV9.ePR8oiVciNg9lAGnkiY01vy3sdylzcO9jQqCph8tklmiQ6cCJenuNl0pB_HzqgMf4iWb-YxlMCdLFcLSrvR2ZH3A34aqr5PVtNP_JtxLDcWs0_QkjqJQp_VQN6V7Zaahtqd3CicKppFYt_ndUrWCTbVkjLMgqXTIPTodo96BH2tReOBaQGN024z-Dpf5gwdSp9E-4CjRcL21qu8QUhGLJt2y-tokN4aKX5pMdwIBbr2kxwkHwVRf4SZItPlfMJbvCSC7ciB886Gw0GOIYuTsQrAtrRUcsgTGiBkp7HvN-kPZse5EgTw-ZVi_xh0u9XBzNYff5a1jrc1vdHLzHeEfUw",
  "refresh_token": "V1kMZsZohLGffvW4dq57IVWEJO44Rx_UPIzGjOszzYs-qGQFfoy9Sv9PtoHTP74vjV-O0gjcZqcZYbLOCzmQHp2Ma0a3WJBBmFRSZF31vwiJg61dWGwK-BMSNMKbYBOM",
  "scope": "openid profile",
  "id_token": "eyJraWQiOiIwOWRmNzRmZi0wMzBhLTRkYzMtYmYxZi05ODAxMDlhYjRkMmQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJhenAiOiJtZXNzYWdpbmctY2xpZW50IiwiYXV0aF90aW1lIjoxNjk3MTc4ODI0LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTcxODA2MjUsImlhdCI6MTY5NzE3ODgyNSwibm9uY2UiOiJyYXZMMVo3eXloZUFYLThva1BCRnN1Q2t2dHZwUmVoc0JSM2ZxeVZjcVFnIiwic2lkIjoiWUVIaHppUS1JVmhxYWNOYlAzdm1qVl84WThLNlpOeXJxa0RXZFl6NVotMCJ9.Q0d6HQZhGFpff9bok2XocqrighQn-y8WYk1wpmmVB1gAQ9GdHJNJnNvdQoxKNGxBtgL2oraBHTZXLxbRCY49DazmkGygyhdKhewfZjC9MIi7oo4-Zp1pLx8ARJpBoAcKgs9rvu_21oEofLC9t97AaokPMsXgcfUs_59LBFd9kI1tyJ3Y7EC9X5Y6ay6Y92--sQbwoRLEd_tVMxgGvT1iEXdqklFlL790UIxQsMtLPviJbIgbnsC89_I4qnY8j5vQEMNbv6zjroubJcpECO70wm1wYNIw2LmuOchpM-sS7cL1_MWegEKp3Iv6JpLSt27nX1JEu5uql7JY-piuJR8XDg",
  "token_type": "Bearer",
  "expires_in": 299
}
```

client 还向 server 发起了`HTTP GET http://localhost:9000/oauth2/jwks`

server 返回：

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "aa6bf576-ea2a-419d-ae24-32219f0e29c3",
      "n": "1dP9tXwIyoON6E2MtoDvzqSUKEgwmlbKrKiVStUxk7cTsJXtLUu5rvF8tY45s-bJiLMOVc4iVUNG93E8Gc2WXGKD7DmwGDoNX81qYpNC2GWmCGv_FpjcszdRyQCaC8B-g6rSfkBIdgNl8X3fI-cgyViZUnz69Hx4FuA9zYaKkLqqG4XoOgmYJyheY3UCHNT2UZMDgoAqpAVMFP4Ihp3xK-iSMaqGdTymzOmocqUZUYuw6TgmE9gJYMQ8OVvkHtgKe3_Pub1kpRHt8BPnJ67yihYhjGig8U-MFz0d6qe61X5s-Ttf4e5QqvD35_6oeu89hiPkNp-Kbs2queORpVX3VQ"
    }
  ]
}
```

client 还向 server 发起了 `GET /userinfo` 这个请求头 header 有 authorization `Bearer eyJraWQiOiIzOGRkMDYxNS03ZDQ2LTQ1MzAtOWNhYi01Zjg3ODYwYjBjN2YiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2OTc0MzYzNjMsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjk3NDM2NjYzLCJpYXQiOjE2OTc0MzYzNjN9.sEcnJGlXu9knX6Nd7F-5oua9reya-Z3nDHm4oMEg99C3YTAYfDZwGnFVgb3SYqG3FovLh9ZpUZbUCeTR5zDCLKmVAV-1ZwEuQkoeoqBDSfzu8yJDbHmyzYbLpFApcHHlXGZrKc5-TgqGn-902aOeimCfgthgHF1yqkbRiuAECznitGuoPIQZJA1M20G8A9VrsDNtE9Vd9E11UX1VgQuCBcrJ31vZGBUpsa_2M8tMTqoA6PQM8ZZQWBZ5YuxkXQX2ov2_DLYrmhd1SkaP8D3kedjxeDWC7-6Fg1c-kf4sjXcIN9AsH7Knp7uUsU066vIbtdx5xgl3PvyQPLlc1yqHXA`

server 返回：

```json
{ "sub": "user1" }
```

前端 302 `http://127.0.0.1:8080/` 302 `http://127.0.0.1:8080/index`

## 认证码

```json
http://127.0.0.1:8080/authorize?grant_type=authorization_code
```

最终读取了 message 列表

## oidc

```json
http://localhost:8080/oauth2/authorization/messaging-client-oidc
```

一般是读取了 userinfo

## 新增 Client

```java
RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
		.clientName("测试form").clientId("form-client")
		// 注意存完的时候是{noop}secret，但是验证过之后就变为了{bcrypt}$2a$10$5igAFJvkf0wg.f5ml2bBgOO.13LmzgOhWwiwZZtTKCjkX0f3wiwJ2
		// {bcrypt}$2a$10$kYEqs8S4mwUSP7ures8ZSuqeng0HI28moJ7htsXcxr3U3QtL31FAC
		// 去除了{bcrypt}之后可以正常验证 new BCryptPasswordEncoder().matches("secret","$2a$10$kYEqs8S4mwUSP7ures8ZSuqeng0HI28moJ7htsXcxr3U3QtL31FAC")
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
```

## scope

范围

### openid

scope 为`openid`的时候，没有授权的这一环节，直接就能获取到信息

```yml
messaging-client-oidc:
  provider: spring
  client-id: form-client
  client-secret: secret
  authorization-grant-type: authorization_code
  redirect-uri: 'http://127.0.0.1:8080/login/oauth2/code/{registrationId}'
  scope: openid
  client-name: messaging-client-oidc
```

```java
// 接口
@GetMapping("/index")
public String index(@AuthenticationPrincipal OAuth2User user,
    @AuthenticationPrincipal OidcUser oidcUser) {

  System.out.println("进入了 index");
  System.out.println(user.toString());
  System.out.println(user.getAttribute("sub").toString());
  System.out.println(user.getAttribute("myname").toString());

  System.out.println(oidcUser.getName());
  System.out.println(oidcUser.toString());

  return "index";
}
```

## IdToken

oidc 流程使用 code 和 state 换取了下面：

```java
{
"scope": "openid username email phone offline_access profile",
"token_type": "Bearer",
"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImVtSzBGbVRIa0xlQWFjeS1YWEpVT3J6SzkxV243TkdoNGFlYUVlSjVQOUUifQ.eyJzdWIiOiI2M2ViNTNjNDQxYTVjMmYwNWYyNGJiMDMiLCJhdWQiOiI2M2ViNDU4NTE1NmQ5NzcxMDFkZDM3NTAiLCJzY29wZSI6Im9wZW5pZCB1c2VybmFtZSBlbWFpbCBwaG9uZSBvZmZsaW5lX2FjY2VzcyBwcm9maWxlIiwiaWF0IjoxNjc2MzY2OTE0LCJleHAiOjE2Nzc1NzY1MTQsImp0aSI6ImVmVU04enNrbl92LXYzeXZfbDVHRV9fQ2JEY0NNZDhEVDFnYVI0bHRqcHAiLCJpc3MiOiJodHRwczovL29pZGMtYXV0aG9yaXphdGlvbi1jb2RlLmF1dGhpbmcuY24vb2lkYyJ9.E3gAYzCQbJmrtM5zl91OPHm2YPnDxzRejw75oVMF1tLqCS0trj6CSBxyxP3Z9t6Eb_oAu1f_3I6XC3KC-l0DTM6q7_R2rnW4LWlik2rDCLuGpG0FqFScLZhwafmrPsVn93yaBQfEEoaLviqKhj3DgOymKqHZzFG3taaz2k_pWsxt4z97DtKjRTiqyMvcSfHsVrjSKELaC-5S_PHPWcQ70iX85IwUb6i5ldZGxYmODCvChNC9p4D4IOT3atvyEHgBTmjA9ZKI-T7hCVHSO91WZY3l1p4iWdi6KdP1oMGTy8WbmUHG9SiWO1Efh_9I5ZpRzVNWXINLv-lZ0d2aZKjg2w",
"expires_in": 1209600,
"id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2M2ViNTNjNDQxYTVjMmYwNWYyNGJiMDMiLCJhdWQiOiI2M2ViNDU4NTE1NmQ5NzcxMDFkZDM3NTAiLCJpYXQiOjE2NzYzNjY5MTQsImV4cCI6MTY3NzU3NjUxNCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWF1dGhvcml6YXRpb24tY29kZS5hdXRoaW5nLmNuL29pZGMiLCJub25jZSI6IjhiYjg3MjdhLWU1MGUtNDUzOC05ZmZmLWZhOTFlNWQ0Y2MwYSIsIm5hbWUiOm51bGwsImdpdmVuX25hbWUiOm51bGwsIm1pZGRsZV9uYW1lIjpudWxsLCJmYW1pbHlfbmFtZSI6bnVsbCwibmlja25hbWUiOm51bGwsInByZWZlcnJlZF91c2VybmFtZSI6bnVsbCwicHJvZmlsZSI6bnVsbCwicGljdHVyZSI6Imh0dHBzOi8vZmlsZXMuYXV0aGluZy5jby9hdXRoaW5nLWNvbnNvbGUvZGVmYXVsdC11c2VyLWF2YXRhci5wbmciLCJ3ZWJzaXRlIjpudWxsLCJiaXJ0aGRhdGUiOm51bGwsImdlbmRlciI6IlUiLCJ6b25laW5mbyI6bnVsbCwibG9jYWxlIjpudWxsLCJ1cGRhdGVkX2F0IjoiMjAyMy0wMi0xNFQwOToyNjoyOC4wNjhaIiwiZW1haWwiOm51bGwsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicGhvbmVfbnVtYmVyIjoiMTg1MTY4Mjk5OTUiLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOnRydWUsInVzZXJuYW1lIjpudWxsfQ.GweoWBCEyHQGP6G9ohbfBMUMALlbZMM9hRAes1De7BM",
"refresh_token": "KanvCEmonS_FgCRdFftOCwka2f8Qjj4tcsIfJF-VC1W"
}
```

其中 id_token 包含了用户的一些信息，并且不是加密的，是一段 jwt

在使用之前需要验证其完整性，本地可以使用 `https://<应用域名>.authing.cn/oidc/.well-known/jwks.json` 中的公钥来验证签名

这里用的是`HTTP GET http://localhost:9000/oauth2/jwks`这个接口进行验证完整性

可以在 [这里](https://jwt.io/?id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbXktZG9tYWluLmF1dGgwLmNvbSIsInN1YiI6ImF1dGgwfDEyMzQ1NiIsImF1ZCI6IjEyMzRhYmNkZWYiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwibmFtZSI6IkphbmUgRG9lIiwiZ2l2ZW5fbmFtZSI6IkphbmUiLCJmYW1pbHlfbmFtZSI6IkRvZSJ9.bql-jxlG9B_bielkqOnjTY9Di9FillFb6IMQINXoYsw&_gl=1*3ty3bo*rollup_ga*NTg5NzIzOTQzLjE2ODY5MDA2NzU.*rollup_ga_F1G3E656YZ*MTY5MDg3MDA0NS43LjAuMTY5MDg3MDA0NS42MC4wLjA.*_ga*NTg5NzIzOTQzLjE2ODY5MDA2NzU.*_ga_QKMSDV5369*MTY5MDg3MDA1MS4yLjAuMTY5MDg3MDA1MS42MC4wLjA.&_ga=2.20231928.1132847582.1690859462-589723943.1686900675) 进行解码查看，三段 base64 分别对应的是一下的手段信息：

![](https://gitee.com/hezf/assets/raw/master/202308011416553.png)

对我们最有用的就是下面的 sub 了，也就是用户 id、还有姓名什么的，这样我们就不需要再去拿着 accesstoken 再去查看用户的基本信息了。

```json
{
  "iss": "http://my-domain.auth0.com",
  "sub": "auth0|123456",
  "aud": "1234abcdef",
  "exp": 1311281970,
  "iat": 1311280970,
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe"
}
```

## Mixed server side templating + Vuejs + Cookie

目前的想法就是这种混合的 App，有一些页面是 spring 项目的模板提供的，其他的增删改查是用的 SPA 去完成的，身份验证是通过 cookie 完成的。

```doc
In some cases you will have a mixed application when part of the front is being generated by some template engine in the server and some will be managed by Vuejs on the client side, and probably you will already have a session based authentication in pace. If that's the case you can still integrate the authentication, remember that at the end the server is only sending the client a cookie with the session ID stored on the server, so if you send back the cookie with every request the server will recognize the user as authenticated and allow the API to be called.

The problem in this case is that you are making requests from different domains so the cookie will not get propagated, you could configure webpack from the Vue side to build the project under project-server/src/main/resources/static and serve the page from Spring so that the front and back end are under the same domain and the cookie should get sent with the ajax requests.


在某些情况下，您会有一个混合应用程序，其中部分前端内容由服务器中的模板引擎生成，而部分内容则由客户端的 Vuejs 管理，而且您可能已经有了基于会话的身份验证。如果是这种情况，你仍然可以集成身份验证，记住服务器最终只是向客户端发送一个 cookie，其中包含存储在服务器上的会话 ID，因此如果你在每次请求时都发回 cookie，服务器就会识别用户已通过身份验证，并允许调用 API。

这种情况下的问题是，您从不同的域发出请求，因此 Cookie 无法传播。您可以在 Vue 端配置 webpack，在 project-server/src/main/resources/static 下构建项目，并从 Spring 提供页面，这样前端和后端就会在同一域下，Cookie 就会随 ajax 请求一起发送。
```

## 未登录

未登录的情况，怎么办？正常的 restful 接口返回吗？
就这么干，还有个问题就是，登录成功后，需要在 security 存储标准的用户信息，否则授权的时候有问题。
