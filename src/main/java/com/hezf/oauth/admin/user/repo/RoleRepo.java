package com.hezf.oauth.admin.user.repo;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import com.hezf.oauth.admin.user.entity.Role;

public interface RoleRepo extends JpaRepository<Role, Long> {

  Role findByName(String name);

  Boolean existsByName(String name);

  @EntityGraph(value = "role-with-permissions")
  @Query(value = "SELECT role FROM Role role WHERE role.id = ?1")
  Role findWithRelations(Number id);

  @EntityGraph(value = "role-with-users")
  @Query(value = "SELECT role FROM Role role WHERE role.id = ?1")
  Role findWithUsers(Number id);

  @EntityGraph(value = "role-with-permissions")
  @Query(value = "SELECT role FROM Role role")
  Page<Role> findRolesWithPermissions(Pageable pageable);

}
