package org.tommap.springsecurityfirstsection.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.tommap.springsecurityfirstsection.model.Customer;
import org.tommap.springsecurityfirstsection.model.dto.LoginRequest;
import org.tommap.springsecurityfirstsection.model.dto.LoginResponse;
import org.tommap.springsecurityfirstsection.repository.CustomerRepository;

import javax.crypto.SecretKey;

import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.JWT_SECRET_KEY;
import static org.tommap.springsecurityfirstsection.constants.ApplicationConstants.DEFAULT_JWT_SECRET_VALUE;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final CustomerRepository customerRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final AuthenticationManager authenticationManager;
//    private final Environment env;

//    @PostMapping("/register")
//    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
//        try {
//            String hashPwd = passwordEncoder.encode(customer.getPwd()); //convert plain text pwd to hash pwd
//            customer.setPwd(hashPwd);
//            customer.setCreateDt(new Date(System.currentTimeMillis()));
//            Customer savedCustomer = customerRepository.save(customer);
//
//            if (savedCustomer.getId() > 0) {
//                return ResponseEntity.status(HttpStatus.CREATED)
//                        .body("Given user details are successfully registered");
//            } else {
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                        .body("User registration failed");
//            }
//        } catch (Exception ex) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body("An exception has occurred: " + ex.getMessage());
//        }
//    }

    @GetMapping("/user")
    public Customer getUserDetailsAfterLogin(Authentication authentication) {
        return customerRepository.findByEmail(authentication.getName()).orElse(null);
    }

//    @PostMapping("/apiLogin")
//    public ResponseEntity<LoginResponse> apiLogin(
//            @RequestBody LoginRequest loginRequest
//    ) {
//        String jwt = "";
//        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(
//                loginRequest.username(), loginRequest.password() //is_authenticated = false
//        );
//
//        Authentication authenticationResp = authenticationManager.authenticate(authentication);
//
//        if (null != authenticationResp && authenticationResp.isAuthenticated() && null != env) {
//                String jwtSecret = env.getProperty(JWT_SECRET_KEY, DEFAULT_JWT_SECRET_VALUE);
//                SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
//
//                java.util.Date now = new java.util.Date();
//                long expirationMillis = 1000L * 60 * 60; // 1 hour
//
//                jwt = Jwts.builder()
//                        .issuer("Tom Coder")
//                        .subject("JWT Token")
//                        .claim("username", authenticationResp.getName())
//                        .claim("authorities", authenticationResp.getAuthorities().stream()
//                                .map(GrantedAuthority::getAuthority)
//                                .collect(Collectors.joining(","))
//                        )
//                        .issuedAt(now)
//                        .expiration(new java.util.Date(now.getTime() + expirationMillis))
//                        .signWith(secretKey)
//                        .compact();
//            }
//
//
//        return ResponseEntity.status(HttpStatus.OK)
//                .header("Authorization", jwt)
//                .body(new LoginResponse(HttpStatus.OK.getReasonPhrase(), jwt));
//    }
}
