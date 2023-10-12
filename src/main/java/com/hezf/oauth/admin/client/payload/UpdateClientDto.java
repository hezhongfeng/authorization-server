package com.hezf.oauth.admin.client.payload;

import jakarta.validation.constraints.NotNull;

public class UpdateClientDto {

  @NotNull(message = "clientName 不能为空")
  private String clientName;

  private String description;

  private String scopes;

  private String redirectUris;

  private String postLogoutRedirectUris;

  public String getClientName() {
    return this.clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public String getDescription() {
    return this.description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public String getScopes() {
    return this.scopes;
  }

  public void setScopes(String scopes) {
    this.scopes = scopes;
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

}
