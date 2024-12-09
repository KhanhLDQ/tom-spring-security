package org.tommap.springsecurityfirstsection.events;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationEvents {
    //by default spring security does not publish AuthorizationGrantedEvent - thousands or millions of events => too noisy for application

    @EventListener
    public void onFailure(AuthorizationDeniedEvent deniedEvent) {
        Authentication authentication = deniedEvent.getAuthentication().get();
        String loggedInUser = (null != authentication)
                ? authentication.getName() : "Unknown";

        String decision = (null != deniedEvent.getAuthorizationDecision())
                ? deniedEvent.getAuthorizationDecision().toString() : "Unknown Reason";

        log.error("Authorization failed for the user: {} due to: {}", loggedInUser, decision);
    }
}
