package com.hezf.oauth.user.service;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.hezf.oauth.user.entity.Role;
import com.hezf.oauth.user.payload.CreateRoleDto;
import com.hezf.oauth.user.payload.UpdateRoleDto;

public interface RoleService {

  public Page<Role> getAllRoles(Pageable pageable);

  public Page<Role> getRolesWithPermissions(Pageable pageable);

  public Role addRole(CreateRoleDto roleDto);

  public Role updateRole(UpdateRoleDto roleDto, Long id);

  public Role getRoleByIdWithPermissions(Long id);

  public Boolean canDelete(List<Long> ids);

  public void deleteRoles(List<Long> ids);
}
