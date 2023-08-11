package com.hezf.oauth.admin.client.service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.authentication.entity.Client;
import com.hezf.oauth.authentication.repository.ClientRepository;

@Service
public class ClientServiceImpl implements ClientService {

  @Autowired
  private ClientRepository clientRepo;

  public Page<Client> getAllClients(Pageable pageable) {
    return clientRepo.findAll(pageable);
  }

  public Client updateClient(UpdateClientDto clientDto, String id) {
    Client client = clientRepo.findById(id).get();
    client.setClientName(clientDto.getClientName());
    client.setScopes(clientDto.getScopes());
    client.setRedirectUris(clientDto.getRedirectUris());
    client.setPostLogoutRedirectUris(clientDto.getPostLogoutRedirectUris());
    clientRepo.save(client);
    return client;
  }

  // @Override
  // public Boolean canDelete(List<Long> ids) {
  // // 只要有一个在使用就不允许删除
  // for (Long id : ids) {
  // Permission permission = permissionRepo.findWithRoles(id);
  // if (permission.getRoles().size() > 0) {
  // return false;
  // }
  // }
  // return true;
  // }

  // @Override
  // public void deletePermissions(List<Long> ids) {
  // for (Long id : ids) {
  // permissionRepo.deleteById(id);
  // }
  // }

}
