package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Accounts;
import org.tommap.springsecurityfirstsection.repository.AccountsRepository;

@RestController
@RequiredArgsConstructor
public class AccountController {
    private final AccountsRepository accountsRepository;

    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam long id) {
        return accountsRepository.findByCustomerId(id);
    }
}
