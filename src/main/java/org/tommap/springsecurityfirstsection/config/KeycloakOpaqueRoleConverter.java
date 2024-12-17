package org.tommap.springsecurityfirstsection.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakOpaqueRoleConverter implements OpaqueTokenAuthenticationConverter {

    @Override
    public Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
//        String username = authenticatedPrincipal.getAttribute("preferred_username");
//        Map<String, Object> realmAccess = authenticatedPrincipal.getAttribute("realm_access");
//        Collection<GrantedAuthority> roles = ((List<String>) realmAccess.get("roles")).stream()
//                .map(role -> "ROLE_" + role)
//                .map(SimpleGrantedAuthority::new)
//                .collect(Collectors.toList());
//
//        return new UsernamePasswordAuthenticationToken(username, null, roles);

        List<String> roles = authenticatedPrincipal.getAttribute("scope");

        if (roles == null || roles.isEmpty()) {
            return new UsernamePasswordAuthenticationToken(authenticatedPrincipal, null, new ArrayList<>());
        }

        Collection<GrantedAuthority> grantedAuthorities = roles.stream()
                .map(role -> "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(authenticatedPrincipal, null, grantedAuthorities);
    }
}
