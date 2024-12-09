package org.tommap.springsecurityfirstsection.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;

import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.JWT_SECRET_KEY;
import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.DEFAULT_JWT_SECRET_VALUE;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JwtValidatorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwt = request.getHeader("Authorization");

        if (null != jwt) {
            try {
                Environment env = getEnvironment();

                if (null != env) {
                    String jwtSecret = env.getProperty(JWT_SECRET_KEY, DEFAULT_JWT_SECRET_VALUE);
                    SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

                    if (null != secretKey) {
                        Claims payload = Jwts.parser().verifyWith(secretKey).build()
                                .parseSignedClaims(jwt)
                                .getPayload();

                        String username = String.valueOf(payload.get("username"));
                        String authorities = String.valueOf(payload.get("authorities"));

                        Authentication authentication = new UsernamePasswordAuthenticationToken(
                                username, null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)
                                //setAuthenticated(true) - successful authentication - not try to authenticate again
                        );
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (Exception exception) {
                throw new BadCredentialsException("Invalid Token received");
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/user");
    }
}
