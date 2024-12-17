package org.tommap.springsecurityfirstsection.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.tommap.springsecurityfirstsection.exceptionhandling.CustomAccessDeniedHandler;
import org.tommap.springsecurityfirstsection.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import org.tommap.springsecurityfirstsection.filter.CsrfCookieFilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/*
    - inside Spring Security framework
        -> execute API (POST - PUT - DELETE - ...) that modify data
        -> by default stop requests due to CSRF protection

    - access to protected APIs
        -> login with correct credentials
        -> cookies (JSESSIONID) is created by spring framework
        -> default session timeout is 30'
        -> after ideal time - users will be redirected to login page
 */

/*
    - CORS & how the browser will know about the configurations that we have done inside the backend?
        + when a browser detects that the traffic is going to a different origin, it will send a preflight request to the server
            - preflight request is going to send by the browser to the backend server before sending the actual API request
        + as part of the preflight request - the browser is going to look for the CORS related configurations from the backend server
        + if the backend replied that  'I'm accepting the request from this origin'
            - backend server has to send header 'Access-Control-Allow-Origin' with details of allowed origins
                + then the browser will send the actual API request
            - otherwise it will block the traffic with CORS related error
 */

/*
    - CSRF
        + by default spring security will block all requests modifying the data (POST - PUT - DELETE ...) without CSRF token
        + only accept GET requests

        + scenarios
            - user login in to netflix.com and the backend server of netflix will verify credentials and provide a cookie which will be stored in the browser against the domain netflix.com
            - user visits a malicious website and the website sends a request to netflix.com to perform illegal actions
            - since the login cookie is stored in the browser, the browser will send the request to the netflix.com with the proper cookie value
            - the backend server of netflix will receive the request and process it because they cannot differentiate between the request from the actual user and the malicious website
            - advantage of the embedded form (maintained by hackers) is that whenever someone is making a request using an embedded form, the browser will think the request is coming
                from the same origin - it will never know that the request is present inside another domain => CORS will not be useful in this scenario
 */

/*
    - DispatcherServlet
        + forward request to the corresponding controller
 */

/*
    - TODO: security github reference - https://github.com/eazybytes/spring-security
 */

@Configuration
@Profile("!prod")
public class SecurityConfig {
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    private String clientSecret;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();

//        http.authorizeHttpRequests(request -> request.anyRequest().denyAll()); //throw 403
        http
//                .securityContext(scc -> scc.requireExplicitSave(false))
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //nowhere we are going to store the token either on the server or on the client
//                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.ALWAYS) //always create a session so that I can reuse the same session to access secured APIs
//                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::newSession)
                           // by default using changeSessionId strategy - should not disable sessionFixation provided by spring security
//                                .invalidSessionUrl("/invalidSession").maximumSessions(5).maxSessionsPreventsLogin(true)
//                )
                /*
                    - control concurrent sessions - set maximumSessions(1) - if users create a new second session then first session is getting invalidated / expired
                    - maxSessionsPreventsLogin(boolean)
                        + if true, prevents a user from authenticating when the maximumSessions(int) has been reached
                        + otherwise (default), the user who authenticates is allowed access and an existing user's session is expired.
                 */
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() { //create an anonymous class that implements CorsConfigurationSource interface
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200")); //config list of origins that are supported by the BE application
                        config.setAllowedMethods(Collections.singletonList("*")); //allow all types of HTTP methods traffic
                        config.setAllowCredentials(true); //accept user credentials or any other applicable cookies from the UI origin to BE server
                        config.setAllowedHeaders(Collections.singletonList("*")); //accept all types of headers from the UI origin
                        config.setExposedHeaders(List.of("Authorization")); //expose headers from BE to UI
                        config.setMaxAge(3600L); //cache the preflight response for 1 hour

                        return config;
                    }
                }))
            .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure())
//            .csrf(AbstractHttpConfigurer::disable)
            .csrf(csrfConfig -> csrfConfig
                    .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                    .ignoringRequestMatchers("/contact", "/register") //ignore CSRF protection for these APIs
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                /*
                    - set cookieHttpOnly=false to allow JS to read the cookie manually because we accept csrf token both
                        as part of cookie and request header
                    - with the help of CookieCsrfTokenRepository, behind the scene the token is going to be generated lazily - mean that
                        the token is only going to be generated when someone try to read this manually because not all requests
                        need to have csrf token
                 */
            .authorizeHttpRequests(request -> request
//                .requestMatchers("/myAccount").hasAuthority("VIEW_ACCOUNT")
//                .requestMatchers("/myBalance").hasAnyAuthority("VIEW_BALANCE", "VIEW_ACCOUNT")
//                .requestMatchers("/myCards").hasAuthority("VIEW_CARDS")
//                .requestMatchers("/myLoans").hasAuthority("VIEW_LOANS")
                .requestMatchers("/myAccount").hasRole("USER") //spring will append ROLE_ prefix to the role name
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/myLoans").authenticated()
//                .requestMatchers("/myLoans").hasRole("USER") //turn-off for demo method level security
                .requestMatchers("/user").authenticated()
                //complex requirements - use access() method - pass Spring-based expression language
                .requestMatchers("/notices", "/contact", "/error", "/register").permitAll()
        );

//        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);

//        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())); //Authorization: Basic [base64_encode(username:password)]
//        http.httpBasic(AbstractHttpConfigurer::disable);

        /*
            - use exceptionHandling to set up global config
            - however authenticationEntryPoint only supports httpBasic (not UI formLogin) -> why we still need global config?
                + spring security may also throw 401 in many other places throughout framework (not only in login flows)
                    -> to handle all scenarios -> can go with global configuration
         */
//        http.exceptionHandling(ehc -> ehc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));

        /*
            - auth server issues JWT token and the token can be validated locally [resource server] with the help of certificate downloaded
                from jwk-set-uri [spring.security.oauth2.resourceserver.jwt.jwk-set-uri]
            - resource server is trying to validate access token locally with this setup and without having any dependency on the auth server
            - only during the very first request, it will try to connect to the auth server to download the certificate from the jwk-set-uri
         */
//        http.oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
//                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter))
//        );

        http.oauth2ResourceServer(rsc -> rsc.opaqueToken(
                otc -> otc
                        .authenticationConverter(new KeycloakOpaqueRoleConverter())
                        .introspectionUri(introspectionUri)
                        .introspectionClientCredentials(clientId, clientSecret)
                )
        );

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        return http.build();
    }

    /*
        - server receives base64-encoded credentials from HTTP request
        - server decodes credentials to get username and password
        - use PasswordEncoder.matches(rawPassword, encodedPassword) to compare
     */

    /*
        - authentication provider
            -> AbstractUserDetailsAuthenticationProvider.authenticate()
            -> DaoAuthenticationProvider.retrieveUser()
            -> UserDetailsService.loadUserByUsername()
            -> DbAuthenticationProvider.additionalAuthenticationChecks()
            -> passwordEncoder.matches(raw_password, stored_password)
            -> convert UserDetails to Authentication
            -> erase credentials after authentication
            -> set authentication to security context
     */

    //convert EazyBank application to resource server => do not perform authentication [registration - login operations] - this is the responsibility of the authorization server [Keycloak]
}
