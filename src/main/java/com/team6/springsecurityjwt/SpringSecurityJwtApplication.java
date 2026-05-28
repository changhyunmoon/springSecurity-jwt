package com.team6.springsecurityjwt;

import com.team6.springsecurityjwt.global.config.CookieProperties;
import com.team6.springsecurityjwt.global.security.jwt.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        JwtProperties.class,
        CookieProperties.class
})
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

}
