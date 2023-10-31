# authorization-server

authorization-server

1. 实现 OAuth2.1 草案的授权方式（认证码包括 Refresh Token、oidc、PKCE 认证 ）
2. client 管理，主要是密码和 redirecturl、logouturl 的管理
3. 用户系统管理，有角色和权限的区分，有管理用户和普通用户
4. 可以统一退出（client 退出后，authorization-server 端也退出，这个可选）
5. 有 client 的 demo（springboot、nestjs，也有前端，可以进行修改用户信息等操作）
6. 支持对 consent 的过期管理（比如说，同意一次一个月内有效这种）

## client 端使用

### 登录

1. 浏览器输入 client 域名，点击登录，跳转到 server 端登录
2. 输入用户名、密码后，跳转回 client 前端，client 前端拿着参数去后端换取信息
3. client 后端拿着参数去获取 userinfo，完成登录和信息获取

也可以实现多应用的登录，例如登录了 server 后，可以随意的在几个 client 之间切换

#### 实现

问题?

1. 登录成功后如何获取 userinfo
2. 如何跳转到前后端分离的页面

### 登出

在 client 前端点击登出，直接在 client 端和 server 都登出，这样可以切换账号

也可以实现多个 client 全部登出

### 应用授权

给应用和用户授权，否则这个应用无法登录微授权的应用

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

这时候 client 会向 server `HTTP POST http://localhost:9000/oauth2/token`,

`messaging-client:secret`取 base64 的值`bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=`，header 里有：

```json
authorization:Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=
Content-Type:application/x-www-form-urlencoded;charset=UTF-8
```

body 是：

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

id_token 中间那段就是信息：

```json
{
  "sub": "user1",
  "aud": "messaging-client",
  "azp": "messaging-client",
  "auth_time": 1697695789,
  "iss": "http://localhost:9000",
  "exp": 1697697739,
  "iat": 1697695939,
  "nonce": "r0QkUee3YVC--qCwZwOGb9twvl0jChxKYh30_Co4",
  "sid": "1DTKImqP15zxZ8C9gsjZMmhGF7G4JRbC0pfnf7olDXQ"
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

## authorization_code

浏览器输入 `http://127.0.0.1:8080/authorize?grant_type=authorization_code` 请求认证码协议

302 `http://127.0.0.1:8080/oauth2/authorization/messaging-client-oidc`

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20profile&state=LiWZmf22cs3Bk82G3fBxowA30_BbwFO-bh4gjT8cHE0%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=2vEIc0MUecrKDz5fmZvFN8Bb1Hlq9BRamg8AQ37ldJM`

302 `http://localhost:9000/login`

填写用户名、密码提交 `POST /login`

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20profile&state=LiWZmf22cs3Bk82G3fBxowA30_BbwFO-bh4gjT8cHE0%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&nonce=2vEIc0MUecrKDz5fmZvFN8Bb1Hlq9BRamg8AQ37ldJM&continue`

302 `http://localhost:9000/oauth2/consent?scope=openid%20profile&client_id=messaging-client&state=4bu0OZkBnEC1JC1SllfLuQUcrEqVa2Z4aoPskhHmygo%3D` 这是授权页面

选择 profile 后提交 `POST /oauth2/authorize`

302 `http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc?code=qKg-2hHmfPbV4UqTvDASOxa4E4BQJf0mQCuFem3Pi_Av93dmneasZPmn2bS8qoAevhUaFBZhnYSpRjxaV9lUrNeKr_H-zavGJLv7cl_9dcb6JPRo5dwUdDY4JMV5pt49&state=LiWZmf22cs3Bk82G3fBxowA30_BbwFO-bh4gjT8cHE0%3D`

这时候 client 向 server 发起 `HTTP POST http://localhost:9000/oauth2/token` 参数 ：

```form
[{grant_type=[authorization_code], code=[qKg-2hHmfPbV4UqTvDASOxa4E4BQJf0mQCuFem3Pi_Av93dmneasZPmn2bS8qoAevhUaFBZhnYSpRjxaV9lUrNeKr_H-zavGJLv7cl_9dcb6JPRo5dwUdDY4JMV5pt49], redirect_uri=[http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc]}]
```

server 返回 ：

```json
{
  "access_token": "eyJraWQiOiJkYWU0ZDM5ZC0xMmVmLTQyZjYtYjk2Mi1jOWMxMWJlM2U0OTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2OTc0MzgyMzcsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjk3NDM4NTM3LCJpYXQiOjE2OTc0MzgyMzd9.HcZIHYrZsA6Imu_P0Xj-oyNHoCK5X0j_N4Q8IAgxJnznrPCFPMecHLYU_rPup9UEUYaYoXzGjZyTB6IvRv_BQ85feHalwJH_ClurtedOg1gc9_qX9JIqUoR8FZbhLY6blE0jLuTed-RF-1vq-Xghp8FYmwLSt9BXq3Bf_YptKI1tWPRg3BIqtYq8iEmg66F82aaChGO3c3nz9Bb8vBlDx2FU6xKWoZElxn63ihqmRJTQvRpIkZqu2hLTIuJtwbxSNyk1FEfESC2q0ZAqU0bG3g03ujxhu9sy8ob_ITjEWmaeLn9j9_6dB3TgzMx_i0nRse-Xx9lO7oPWjbXP3EvcAw",
  "refresh_token": "zPKW_BTfk-C9RroqFSMXBQ2NOi0cBMzG1H9Qghh4O0H1j65bqhTirbAEAMR47A5g4uxUDnf3gouN6KCC537Fku4Xv_LwbDCyg700Fmq3j_WnmJXO6sb3VXTd-QoEaBv8",
  "scope": "openid profile",
  "id_token": "eyJraWQiOiJkYWU0ZDM5ZC0xMmVmLTQyZjYtYjk2Mi1jOWMxMWJlM2U0OTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJhenAiOiJtZXNzYWdpbmctY2xpZW50IiwiYXV0aF90aW1lIjoxNjk3NDM4MjM3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTc0NDAwMzcsImlhdCI6MTY5NzQzODIzNywibm9uY2UiOiIydkVJYzBNVWVjcktEejVmbVp2Rk44QmIxSGxxOUJSYW1nOEFRMzdsZEpNIiwic2lkIjoibWV4ZU5mQ3lQUlRwS1YyM0RLU0NIakFlTGptTS1YYXdkS2FzYjBIRG4xRSJ9.PRdhc2iv6z9PwkfP0DRRhqtbSNYLlt57P_3vhgvhGqwI78NFNMOH8xLTf6QKFPZC_ZA7mEhRgkw7jR_Xmmhj0Fi5MsuL4KRyLhYNkFCV_5lrxfGkhUZEPClAb9Odu0Dglph8pg6sVsxtUAAuLIo-XCcCRelc1WxFP1ywylZJrj4d377nyCipFz2haIiemrXf-G-WL9lC4ghL-phl6W2MANC53yPEnIU4vKMu2Dd83x8F-emLDCxksvwgqt6NxJjhJavzdSf3WXNzh14EHhqsIWSXprmeb48StNKzzabvSpQg7mSlSImXrpWpSzpJi9or0oMCF1ZfpU3xq1Qn_EziXw",
  "token_type": "Bearer",
  "expires_in": 299
}
```

client 发起 `HTTP GET http://localhost:9000/oauth2/jwks`

server 返回：

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "dae4d39d-12ef-42f6-b962-c9c11be3e495",
      "n": "uyCF4Rx4EAMCZchrJ81a4bvR1KYM4rFMRJV5tQuFtcwzF4xu554SGmAL5VWWDXv1jHhInk9IDY_wBkXX9cZMYcGeEhf7Pn9TUIAcyL7FpOpatl9K7I4Ycv-xO19VBtRwq0hhjeQcmyusFS0S48dnjE1kwbW0JeNAraovN2fgjw16mE2Uges_3gO8iXyVrpVQ2QXsAy8eX-KraTRkQbb3Ydw0-XfhK9FwVzhClgoMQDZu-_gjFKEUcAoWdAkOKUE2EYNRPEohN5eu48rm2AtVTf0bEcHo4qOOF25KyGyMOVHBZlZcgG4ytyeQelhtbr_yyclE6X7gT4IQ4Vv9eNoV8w"
    }
  ]
}
```

client 发起 ：`HTTP GET http://localhost:9000/userinfo`

server 返回：

```json
{ "sub": "user1" }
```

302 `http://127.0.0.1:8080/authorize?grant_type=authorization_code&continue`

302 `http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read%20message.write&state=fpa90wP0eJvFBBU3-55-FnwLO246NFw8YOummQt87os%3D&redirect_uri=http://127.0.0.1:8080/authorized`

302 `http://localhost:9000/oauth2/consent?scope=message.read%20message.write&client_id=messaging-client&state=3ZTByZic4Bwbt0tlLlR0C-8MwKK_vXyCOVlRfh1jrHs%3D`，前端显示 scope：

选择后提交：`POST /oauth2/authorize`

302 `http://127.0.0.1:8080/authorized?code=2GTeTfP5ELaisreRpdVzMRMLWyvL3ZbXhjcNZwSoP618kx69J3mXxQc0Ah-qNGrve1YYrXqJAt9octPly6XbaapSy2OGxID4_FD4WUVmUSiFj89JY8WSHOVAd-O5MEHa&state=fpa90wP0eJvFBBU3-55-FnwLO246NFw8YOummQt87os%3D`

client 向 server 发起：`HTTP POST http://localhost:9000/oauth2/token` ，参数：

```form
[{grant_type=[authorization_code], code=[2GTeTfP5ELaisreRpdVzMRMLWyvL3ZbXhjcNZwSoP618kx69J3mXxQc0Ah-qNGrve1YYrXqJAt9octPly6XbaapSy2OGxID4_FD4WUVmUSiFj89JY8WSHOVAd-O5MEHa], redirect_uri=[http://127.0.0.1:8080/authorized]}]
```

server 回复：

```json
{
  "access_token": "eyJraWQiOiJkYWU0ZDM5ZC0xMmVmLTQyZjYtYjk2Mi1jOWMxMWJlM2U0OTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2OTc0MzkwNjksInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjk3NDM5MzY5LCJpYXQiOjE2OTc0MzkwNjl9.l3Kt5ZXAsjdcDBb4gUYJYIWH31JRnjguwSFdXbBhJaLfdw-CNNHuspvbUyn9OQjNVVFDXxbUV1xdkajZoC22Yuj62i4V0P6hxeUgIYqXdVKA7xQ5zVBszRMnFz7pXHbppjg_44D0MvMdz7m_H8DufKIRw_TwIx5LrXgr7TOhZiaKxxUeZzGvzJUTdD-X2CFoK2VyoOPPm6G6b5pQiGguxyjAwxEAPvsGDxyxLXxbUbXwi9SierTPfcDlMK31Ykc67WEdgS2D5gmE4GvwtkG5Ou5Q4FV-iYOyWAapYetcaw-BB3-xfYtOejMWUmRDA3wU3_u30Iua1_jM8R01-ciPOg",
  "refresh_token": "tL16Eofu5oixiCAcoOneOXtL5NUgPhC9_jJRgWQKnh808N86qdD0svgZ8fO1IdvMQXTP69V014qwFtch6txk0FRqVhZVfFOO9lvW3PfeUB_Iber4fRLLTz0oqo28Srze",
  "scope": "message.read message.write",
  "token_type": "Bearer",
  "expires_in": 299
}
```

302 `http://127.0.0.1:8080/authorize?grant_type=authorization_code&continue&continue`

client 向 resource 发起`HTTP GET http://127.0.0.1:8090/messages`

resource 向 server 发起：`HTTP GET http://localhost:9000/.well-known/openid-configuration`

server 返回：

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

resource 向 server 发起了`HTTP GET http://localhost:9000/oauth2/jwks`

server 返回：

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "dae4d39d-12ef-42f6-b962-c9c11be3e495",
      "n": "uyCF4Rx4EAMCZchrJ81a4bvR1KYM4rFMRJV5tQuFtcwzF4xu554SGmAL5VWWDXv1jHhInk9IDY_wBkXX9cZMYcGeEhf7Pn9TUIAcyL7FpOpatl9K7I4Ycv-xO19VBtRwq0hhjeQcmyusFS0S48dnjE1kwbW0JeNAraovN2fgjw16mE2Uges_3gO8iXyVrpVQ2QXsAy8eX-KraTRkQbb3Ydw0-XfhK9FwVzhClgoMQDZu-_gjFKEUcAoWdAkOKUE2EYNRPEohN5eu48rm2AtVTf0bEcHo4qOOF25KyGyMOVHBZlZcgG4ytyeQelhtbr_yyclE6X7gT4IQ4Vv9eNoV8w"
    }
  ]
}
```

resource 返回 client：

```form
[{Message 1, Message 2, Message 3}]
```

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

可以在 [这里](https://jwt.io) 进行解码查看，三段 base64 分别对应的是一下的手段信息：

对我们最有用的就是就是用户 id、还有姓名什么的，这样我们就不需要再去拿着 accesstoken 再去查看用户的基本信息了。

```json
{
  "sub": "63eb53c441a5c2f05f24bb03",
  "aud": "63eb4585156d977101dd3750",
  "iat": 1676366914,
  "exp": 1677576514,
  "iss": "https://oidc-authorization-code.authing.cn/oidc",
  "nonce": "8bb8727a-e50e-4538-9fff-fa91e5d4cc0a",
  "name": null,
  "given_name": null,
  "middle_name": null,
  "family_name": null,
  "nickname": null,
  "preferred_username": null,
  "profile": null,
  "picture": "https://files.authing.co/authing-console/default-user-avatar.png",
  "website": null,
  "birthdate": null,
  "gender": "U",
  "zoneinfo": null,
  "locale": null,
  "updated_at": "2023-02-14T09:26:28.068Z",
  "email": null,
  "email_verified": false,
  "phone_number": "18516829995",
  "phone_number_verified": true,
  "username": null
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
