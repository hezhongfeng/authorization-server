package com.hezf.oauth.admin.user.service;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.hezf.oauth.admin.user.entity.Permission;
import com.hezf.oauth.admin.user.payload.UpdatePermissionDto;

public interface PermissionService {

  public Page<Permission> getAllPermissions(Pageable pageable);

  public Permission updatePermission(UpdatePermissionDto roleDto, Long id);

  public Boolean canDelete(List<Long> ids);

  public void deletePermissions(List<Long> ids);
}
