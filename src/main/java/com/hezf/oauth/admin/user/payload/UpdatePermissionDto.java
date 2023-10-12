package com.hezf.oauth.admin.user.payload;

import jakarta.validation.constraints.NotNull;

public class UpdatePermissionDto {

  @NotNull(message = "name 不能为空")
  private String name;

  private String description;

  public String getName() {
    return this.name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getDescription() {
    return this.description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

}
