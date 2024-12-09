package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Contact;
import org.tommap.springsecurityfirstsection.repository.ContactRepository;

import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@RestController
@RequiredArgsConstructor
public class ContactController {
    private final ContactRepository contactRepository;

    @PostMapping("/contact")
//    @PreFilter("filterObject.contactName != 'Test'") //filter input parameters
    @PostFilter("filterObject.contactName != 'Test'") //filter response value
    public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
        List<Contact> response = new ArrayList<>();

        if (!contacts.isEmpty()) {
            Contact contact = contacts.get(0);
            contact.setContactId(getServiceReqNumber());
            contact.setCreateDt(new Date(System.currentTimeMillis()));

            Contact savedContact = contactRepository.save(contact);
            response.add(savedContact);
        }

        return response;
    }

    public String getServiceReqNumber() {
        Random random = new Random();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
