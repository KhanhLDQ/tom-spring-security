package org.tommap.springsecurityfirstsection.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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

import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/*
    - inside Spring Security framework
        -> execute API (POST - PUT - DELETE - ...) that modify data
        -> by default stop requests due to CSRF protection
 */

@Configuration
@Profile("prod")
public class SecurityProdConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        //can read CSRF token value receiving inside request-headers from client-side

        http
//                .securityContext(scc -> scc.requireExplicitSave(false))
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                        .invalidSessionUrl("/invalidSession").maximumSessions(1).maxSessionsPreventsLogin(true)
                .cors(corsConfig -> corsConfig.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200")); //conflicts with requiresSecure() - HTTPS
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setMaxAge(3600L);

                    return config;
                }))
                .requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) //any request to backend application must be secure with HTTPS
//                .csrf(AbstractHttpConfigurer::disable)
                .csrf(csrfConfig -> csrfConfig
                        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/contact", "/register") //ignore CSRF protection for these APIs
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests(request -> request
//                    .requestMatchers("/myAccount").hasAuthority("VIEW_ACCOUNT")
//                    .requestMatchers("/myBalance").hasAnyAuthority("VIEW_BALANCE", "VIEW_ACCOUNT")
//                    .requestMatchers("/myCards").hasAuthority("VIEW_CARDS")
//                    .requestMatchers("/myLoans").hasAuthority("VIEW_LOANS")
                    .requestMatchers("/myAccount").hasRole("USER")
                    .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                    .requestMatchers("/myCards").hasRole("USER")
                    .requestMatchers("/myLoans").hasRole("USER")
                    .requestMatchers("/user").authenticated()
                    .requestMatchers("/notices", "/contact", "/error", "/register").permitAll()
                );

//        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);

//        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())); //Authorization: Basic [base64_encode(username:password)]
//        http.httpBasic(AbstractHttpConfigurer::disable);

        http.oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter))
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
}
