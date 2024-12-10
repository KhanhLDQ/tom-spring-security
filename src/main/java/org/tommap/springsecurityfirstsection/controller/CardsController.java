package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Cards;
import org.tommap.springsecurityfirstsection.model.Customer;
import org.tommap.springsecurityfirstsection.repository.CardsRepository;
import org.tommap.springsecurityfirstsection.repository.CustomerRepository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class CardsController {
    private final CardsRepository cardsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myCards")
    public List<Cards> getCardsDetails(@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);

        if (optionalCustomer.isPresent()) {
            return cardsRepository.findByCustomerId(optionalCustomer.get().getId());
        } else {
            return Collections.emptyList();
        }
    }
}
