package org.tommap.springsecurityfirstsection.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;

import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.DEFAULT_JWT_SECRET_VALUE;
import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.JWT_SECRET_KEY;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (null != authentication) {
            Environment env = getEnvironment();

            if (null != env) {
                String jwtSecret = env.getProperty(JWT_SECRET_KEY, DEFAULT_JWT_SECRET_VALUE);
                SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

                Date now = new Date();
                long expirationMillis = 1000L * 60 * 60; // 1 hour

                String jwt = Jwts.builder()
                        .issuer("TomCoder")
                        .subject("JWT Token")
                        .claim("username", authentication.getName())
                        .claim("authorities", authentication.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(","))
                        )
                        .issuedAt(now)
                        .expiration(new Date(now.getTime() + expirationMillis))
                        .signWith(secretKey) //generate digital signature
                        .compact();//return JWT Token in String format

                response.setHeader("Authorization", jwt);
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/user");
    }
}
