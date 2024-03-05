package me.silvernine.jwttutorial.config;


import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/hello").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web) -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().requestMatchers("/h2-coneole/**", "/favicon.ico", "/resources/**", "/error");
        };
    }
}
