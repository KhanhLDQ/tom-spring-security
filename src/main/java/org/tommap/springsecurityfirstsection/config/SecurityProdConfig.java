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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.tommap.springsecurityfirstsection.exceptionhandling.CustomAccessDeniedHandler;
import org.tommap.springsecurityfirstsection.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import org.tommap.springsecurityfirstsection.filter.AuthoritiesLoggingAfterFilter;
import org.tommap.springsecurityfirstsection.filter.AuthoritiesLoggingAtFilter;
import org.tommap.springsecurityfirstsection.filter.CsrfCookieFilter;
import org.tommap.springsecurityfirstsection.filter.JwtGeneratorFilter;
import org.tommap.springsecurityfirstsection.filter.JwtValidatorFilter;
import org.tommap.springsecurityfirstsection.filter.RequestValidationBeforeFilter;

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
                        .ignoringRequestMatchers("/contact", "/register", "/apiLogin") //ignore CSRF protection for these APIs
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
//                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
//                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JwtValidatorFilter(), BasicAuthenticationFilter.class)
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
                    .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession", "/apiLogin").permitAll()
                );

        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);

        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())); //Authorization: Basic [base64_encode(username:password)]
//        http.httpBasic(AbstractHttpConfigurer::disable);

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        return http.build();
    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) { //connect to database
//        return new JdbcUserDetailsManager(dataSource);
//    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}User12345@U") //no encoding is applied at this point => save raw password directly
//                .authorities("read")
//                .build();
//
//        UserDetails admin = User
//                .withUsername("admin")
//                .password("{bcrypt}$2a$12$CGTLBP6igN3rfkgMkCQAD.ECrvM0FIcfLYBPEXbvFoSAnkSnqaf9C") //Admin12345@A
//                .authorities("admin")
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); //never try to hard code a particular PasswordEncoder
        /*
            - hashing - format where your password is going to be encrypted - no one should be able to reverse the plain text password - one-way process
            - DelegatingPasswordEncoder allows system to handle multiple password encoders by using a prefix in the stored password
         */
    }

    /*
        - server receives base64-encoded credentials from HTTP request
        - server decodes credentials to get username and password
        - use PasswordEncoder.matches(rawPassword, encodedPassword) to compare
     */

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() { //avoid simple password ... - since Spring 6.3
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

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

    @Bean
    public AuthenticationManager authenticationManager(
            TomUserDetailsManager userDetailsManager,
            PasswordEncoder passwordEncoder
    ) {
        TomProdDaoAuthenticationProvider daoAuthenticationProvider = new TomProdDaoAuthenticationProvider(userDetailsManager, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(daoAuthenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);

        return providerManager;
    }
}
