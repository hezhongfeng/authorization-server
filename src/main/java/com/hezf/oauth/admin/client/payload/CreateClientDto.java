package com.hezf.oauth.admin.client.payload;

import jakarta.validation.constraints.NotNull;

public class CreateClientDto {

  @NotNull(message = "clientName 不能为空")
  private String clientName;

  @NotNull(message = "clientId 不能为空")
  private String clientId;

  @NotNull(message = "clientSecret 不能为空")
  private String clientSecret;

  private String redirectUris;

  private String postLogoutRedirectUris;


  public String getClientName() {
    return this.clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public String getClientId() {
    return this.clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getRedirectUris() {
    return this.redirectUris;
  }

  public void setRedirectUris(String redirectUris) {
    this.redirectUris = redirectUris;
  }

  public String getPostLogoutRedirectUris() {
    return this.postLogoutRedirectUris;
  }

  public void setPostLogoutRedirectUris(String postLogoutRedirectUris) {
    this.postLogoutRedirectUris = postLogoutRedirectUris;
  }


  public String getClientSecret() {
    return this.clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

}
