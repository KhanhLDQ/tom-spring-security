package org.tommap.springsecurityfirstsection.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.tommap.springsecurityfirstsection.model.Loans;

import java.util.List;

public interface LoanRepository extends CrudRepository<Loans, Long> {
    /*
        - perform method level security | invocation authorization
            + @PreAuthorize - verify roles | authorities | input parameters
            + @PostAuthorize - verify return value
     */
    @PreAuthorize("hasRole('USER')")
    List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);
}
