package com.hezf.oauth.admin.client.controller;

import java.util.HashSet;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.admin.client.service.ClientService;
import com.hezf.oauth.admin.user.config.DeleteListRequest;
import com.hezf.oauth.admin.user.config.ListRequest;
import com.hezf.oauth.admin.user.config.ListResponse;
import com.hezf.oauth.admin.user.config.RespResult;
import com.hezf.oauth.admin.user.entity.Permission;
import com.hezf.oauth.admin.user.entity.Role;
import com.hezf.oauth.admin.user.payload.CreatePermissionDto;
import com.hezf.oauth.admin.user.payload.UpdatePermissionDto;
import com.hezf.oauth.admin.user.repo.PermissionRepo;
import com.hezf.oauth.admin.user.service.PermissionService;
import com.hezf.oauth.authentication.entity.Client;
import com.hezf.oauth.authentication.repository.ClientRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "权限", description = "权限相关CRUD接口")
@RestController
@RequestMapping("/api/admin/v1/clients")
@PreAuthorize("@rbacAuthorityService.hasPermissions('admin')") // 必须具有 admin 权限才能访问
public class AdminClientController {

  @Autowired
  private ClientRepository clientRepo;

  @Autowired
  private ClientService clientService;

  @Operation(summary = "查询client列表")
  @GetMapping
  public RespResult<ListResponse<Client>> getClients(ListRequest listRequest) {

    Sort sort = Sort.by(Sort.Direction.DESC, "id");
    int pageIndex = 0;
    int pageSize = 10;
    if (listRequest.getPage() != null) {
      pageIndex = listRequest.getPage() - 1;
    }

    if (listRequest.getPageSize() != null) {
      pageSize = listRequest.getPageSize();
    }
    // 分页
    Pageable pageable = PageRequest.of(pageIndex, pageSize, sort);

    Page<Client> clientsPage = clientService.getAllClients(pageable);

    ListResponse<Client> listResponse = new ListResponse<Client>();
    listResponse.setCount(clientsPage.getTotalElements());

    List<Client> clientList = clientsPage.getContent();

    for (Client client : clientList) {
      client.setClientSecret(null);
    }

    listResponse.setList(clientsPage.getContent());
    return new RespResult<ListResponse<Client>>(200, "", listResponse);
  }

  // @Operation(summary = "创建权限")
  // @PostMapping
  // public RespResult<Permission> createPermission(
  // @RequestBody @Validated CreatePermissionDto permissionDto) {

  // if (permissionRepo.existsByName(permissionDto.getName())) {
  // return new RespResult<Permission>(201, "无法创建，权限名已存在", null);
  // }

  // if (permissionRepo.existsByKeyName(permissionDto.getKeyName())) {
  // return new RespResult<Permission>(201, "无法创建，keyName已存在", null);
  // }

  // Permission permission = new Permission();
  // permission.setName(permissionDto.getName());
  // permission.setKeyName(permissionDto.getKeyName());
  // permission.setDescription(permissionDto.getDescription());

  // permissionRepo.save(permission);

  // permission.setRoles(new HashSet<>());
  // return new RespResult<Permission>(200, "", permission);
  // }

  @Operation(summary = "查看client")
  @GetMapping("/{id}")
  public RespResult<Object> getClient(@PathVariable("id") String id) {
    Client client = clientRepo.findById(id).get();

    // 隐藏密码信息
    client.setClientSecret(null);

    return new RespResult<Object>(200, "", client);
  }

  @Operation(summary = "更新Client")
  @PutMapping("/{id}")
  public RespResult<Object> updatePermission(@RequestBody @Validated UpdateClientDto clientDto,
      @PathVariable("id") String id) {

    Client client = clientRepo.findById(id).get();

    if (client == null) {
      return new RespResult<Object>(201, "无法更新，参数错误", null);
    }

    clientService.updateClient(clientDto, id);

    return new RespResult<Object>(200, "", null);
  }

  // @Operation(summary = "删除权限")
  // @DeleteMapping()
  // public RespResult<Object> deleteRoles(
  // @RequestBody @Validated DeleteListRequest deleteListRequest) {

  // if (!permissionService.canDelete(deleteListRequest.getIds())) {
  // return new RespResult<Object>(201, "无法删除，权限已绑定角色", null);
  // }

  // // 执行删除
  // permissionService.deletePermissions(deleteListRequest.getIds());
  // return new RespResult<Object>(200, "", null);
  // }

}
