package com.hezf.oauth.admin.client.service;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.admin.user.entity.Permission;
import com.hezf.oauth.admin.user.payload.UpdatePermissionDto;
import com.hezf.oauth.authentication.entity.Client;

public interface ClientService {

  public Page<Client> getAllClients(Pageable pageable);

  public Client updateClient(UpdateClientDto clientDto, String id);

  // public Boolean canDelete(List<Long> ids);

  // public void deletePermissions(List<Long> ids);
}
