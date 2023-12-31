package com.hezf.oauth.admin.client.controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.hezf.oauth.admin.client.payload.CreateClientDto;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.admin.client.service.ClientService;
import com.hezf.oauth.admin.user.config.ListRequest;
import com.hezf.oauth.admin.user.config.ListResponse;
import com.hezf.oauth.admin.user.config.RespResult;
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

  @Operation(summary = "创建Client")
  @PostMapping
  public RespResult<Client> createClient(@RequestBody @Validated CreateClientDto clientDto) {

    if (clientRepo.existsByClientId(clientDto.getClientId())) {
      return new RespResult<Client>(201, "无法创建，权限名已存在", null);
    }
    clientService.createClient(clientDto);
    return new RespResult<Client>(200, "创建成功", null);
  }

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
  public RespResult<Object> updateClient(@RequestBody @Validated UpdateClientDto clientDto,
      @PathVariable("id") String id) {

    Client client = clientRepo.findById(id).get();

    if (client == null) {
      return new RespResult<Object>(201, "参数错误", null);
    }

    clientService.updateClient(clientDto, id);

    return new RespResult<Object>(200, "", null);
  }

}
