package org.tommap.springsecurityfirstsection.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Notice;
import org.tommap.springsecurityfirstsection.repository.NoticeRepository;

import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequiredArgsConstructor
//@CrossOrigin(origins = "http://localhost:4200")
/*
    - any request that is coming from this origin is going to be accepted by this controller
    - use '*' to accept all origins - only be useful for the scenario when you're trying to expose your API as an opensource project
    - can mention multiple origins by comma separated values
    - issue with this approach is that you need to define this annotation in every controller
 */
public class NoticesController {
    private final NoticeRepository noticeRepository;

    @GetMapping("/notices")
    public ResponseEntity<List<Notice>> getNotices() {
        List<Notice> notices = noticeRepository.findAllActiveNotices();
        if (notices != null) {
            return ResponseEntity.ok()
                    .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                    //tell client cache to keep the response for 60 seconds - after that it should make a new request
                    .body(notices);
        } else {
            return null;
        }
    }
}