package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Accounts;
import org.tommap.springsecurityfirstsection.model.Customer;
import org.tommap.springsecurityfirstsection.repository.AccountsRepository;
import org.tommap.springsecurityfirstsection.repository.CustomerRepository;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class AccountController {
    private final AccountsRepository accountsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);

        if (optionalCustomer.isPresent()) {
            return accountsRepository.findByCustomerId(optionalCustomer.get().getId());
        } else {
            return null;
        }
    }
}
