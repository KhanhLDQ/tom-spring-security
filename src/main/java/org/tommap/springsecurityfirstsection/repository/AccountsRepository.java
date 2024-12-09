package org.tommap.springsecurityfirstsection.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.tommap.springsecurityfirstsection.model.Accounts;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {
    Accounts findByCustomerId(long customerId);
}
