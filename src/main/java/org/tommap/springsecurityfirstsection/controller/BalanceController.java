package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.AccountTransactions;
import org.tommap.springsecurityfirstsection.model.Customer;
import org.tommap.springsecurityfirstsection.repository.AccountTransactionsRepository;
import org.tommap.springsecurityfirstsection.repository.CustomerRepository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class BalanceController {
    private final AccountTransactionsRepository accountTransactionsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);

        if (optionalCustomer.isPresent()) {
            return accountTransactionsRepository.findByCustomerIdOrderByTransactionDtDesc(optionalCustomer.get().getId());
        } else {
            return Collections.emptyList();
        }
    }
}
