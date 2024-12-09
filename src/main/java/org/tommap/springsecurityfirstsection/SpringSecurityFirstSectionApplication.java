package org.tommap.springsecurityfirstsection;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
//@EnableWebSecurity //optional - Spring Boot is smart enough to
// enable security based upon the dependencies that it finds inside pom.xml
@EnableMethodSecurity(prePostEnabled = true, jsr250Enabled = true, securedEnabled = true)
public class SpringSecurityFirstSectionApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityFirstSectionApplication.class, args);
    }

}
