package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Cards;
import org.tommap.springsecurityfirstsection.repository.CardsRepository;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class CardsController {
    private final CardsRepository cardsRepository;

    @GetMapping("/myCards")
    public List<Cards> getCardsDetails(@RequestParam long id) {
        return cardsRepository.findByCustomerId(id);
    }
}
