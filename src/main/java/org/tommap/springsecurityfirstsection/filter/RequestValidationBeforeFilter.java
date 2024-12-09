package org.tommap.springsecurityfirstsection.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RequestValidationBeforeFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String authorization = req.getHeader(HttpHeaders.AUTHORIZATION);

        if (null != authorization) {
            authorization = authorization.trim();

            if (StringUtils.startsWithIgnoreCase(authorization, "Basic ")) {
                byte[] base64Token = authorization.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;

                try {
                    decoded = Base64.getDecoder().decode(base64Token);
                    String token = new String(decoded, StandardCharsets.UTF_8); //username:password
                    int delimiter = token.indexOf(":");

                    if (-1 == delimiter) {
                        throw new BadCredentialsException("Invalid basic authentication token");
                    }

                    String username = token.substring(0, delimiter);

                    if (username.toLowerCase().contains("test")) {
                        res.setStatus(HttpServletResponse.SC_BAD_REQUEST);

                        return;
                    }
                } catch (IllegalArgumentException exception) {
                    throw new BadCredentialsException("Failed to decode basic authentication token");
                }
            }
        }

        chain.doFilter(request, response);
    }
}
