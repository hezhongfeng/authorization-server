package com.hezf.oauth.admin.client.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.hezf.oauth.admin.client.payload.CreateClientDto;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.authentication.entity.Client;

public interface ClientService {

  public Page<Client> getAllClients(Pageable pageable);

  public void createClient(CreateClientDto createClientDto);

  public Client updateClient(UpdateClientDto updateClientDto, String id);

}
