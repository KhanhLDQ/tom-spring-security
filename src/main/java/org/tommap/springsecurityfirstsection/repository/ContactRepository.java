package org.tommap.springsecurityfirstsection.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.tommap.springsecurityfirstsection.model.Contact;

@Repository
public interface ContactRepository extends CrudRepository<Contact, String> {

}
