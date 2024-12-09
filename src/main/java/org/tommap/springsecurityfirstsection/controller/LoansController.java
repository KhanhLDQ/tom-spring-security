package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Loans;
import org.tommap.springsecurityfirstsection.repository.LoanRepository;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {
    private final LoanRepository loanRepository;

    @GetMapping("/myLoans")
    public List<Loans> getLoanDetails(@RequestParam long id) {
        return loanRepository.findByCustomerIdOrderByStartDtDesc(id);
    }
}
