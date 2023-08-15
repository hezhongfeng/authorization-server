package com.hezf.oauth.admin.client.service;

import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;
import com.hezf.oauth.admin.client.payload.CreateClientDto;
import com.hezf.oauth.admin.client.payload.UpdateClientDto;
import com.hezf.oauth.authentication.entity.Client;
import com.hezf.oauth.authentication.repository.ClientRepository;

@Service
public class ClientServiceImpl implements ClientService {

  @Autowired
  private ClientRepository clientRepo;

  @Autowired
  private RegisteredClientRepository registeredClientRepository;

  public Page<Client> getAllClients(Pageable pageable) {
    return clientRepo.findAll(pageable);
  }

  public void createClient(CreateClientDto createClientDto) {

    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientName(createClientDto.getClientName()).clientId(createClientDto.getClientId())
        // 注意存完的时候是{noop}secret，但是验证过之后就变为了{bcrypt}$2a$10$5igAFJvkf0wg.f5ml2bBgOO.13LmzgOhWwiwZZtTKCjkX0f3wiwJ2
        .clientSecret("{noop}" + createClientDto.getClientSecret()).clientIdIssuedAt(Instant.now())
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri(createClientDto.getRedirectUris())
        .postLogoutRedirectUri(createClientDto.getPostLogoutRedirectUris())
        // openid is necessary
        .scope(OidcScopes.OPENID)
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();

    registeredClientRepository.save(registeredClient);
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

}
