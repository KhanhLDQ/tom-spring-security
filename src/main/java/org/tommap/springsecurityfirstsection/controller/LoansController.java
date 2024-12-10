package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Customer;
import org.tommap.springsecurityfirstsection.model.Loans;
import org.tommap.springsecurityfirstsection.repository.CustomerRepository;
import org.tommap.springsecurityfirstsection.repository.LoanRepository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class LoansController {
    private final LoanRepository loanRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myLoans")
    public List<Loans> getLoanDetails(@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);

        if (optionalCustomer.isPresent()) {
            return loanRepository.findByCustomerIdOrderByStartDtDesc(optionalCustomer.get().getId());
        } else {
            return Collections.emptyList();
        }
    }
}
