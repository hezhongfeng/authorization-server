package com.hezf.oauth.user.service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.hezf.oauth.user.entity.Permission;
import com.hezf.oauth.user.payload.UpdatePermissionDto;
import com.hezf.oauth.user.repo.PermissionRepo;

@Service
public class PermissionServiceImpl implements PermissionService {

  @Autowired
  private PermissionRepo permissionRepo;

  public Page<Permission> getAllPermissions(Pageable pageable) {
    return permissionRepo.findAll(pageable);
  }

  public Permission updatePermission(UpdatePermissionDto roleDto, Long id) {
    Permission permission = permissionRepo.findById(id).get();
    permission.setName(roleDto.getName());
    permission.setDescription(roleDto.getDescription());
    permissionRepo.save(permission);
    return permission;
  }

  @Override
  public Boolean canDelete(List<Long> ids) {
    // 只要有一个在使用就不允许删除
    for (Long id : ids) {
      Permission permission = permissionRepo.findWithRoles(id);
      if (permission.getRoles().size() > 0) {
        return false;
      }
    }
    return true;
  }

  @Override
  public void deletePermissions(List<Long> ids) {
    for (Long id : ids) {
      permissionRepo.deleteById(id);
    }
  }

}
