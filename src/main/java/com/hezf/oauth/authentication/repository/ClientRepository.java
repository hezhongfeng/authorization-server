package com.hezf.oauth.authentication.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.hezf.oauth.authentication.entity.Client;

public interface ClientRepository extends JpaRepository<Client, String> {
  Optional<Client> findByClientId(String clientId);

  Boolean existsByClientId(String name); 
}
