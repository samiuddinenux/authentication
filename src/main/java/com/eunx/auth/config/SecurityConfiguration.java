package com.eunx.auth.config;

import com.eunx.auth.security.JwtAuthenticationEntryPoint;
import com.eunx.auth.security.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtFilter jwtFilter;

    public SecurityConfiguration(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtFilter jwtFilter) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public HttpFirewall customHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedPercent(true);
        firewall.setAllowSemicolon(true);
        firewall.setAllowBackSlash(true);
        firewall.setAllowUrlEncodedSlash(true);
        return firewall;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests(auth -> auth
                        // Fix: Use AntPathRequestMatcher with HttpMethod for OPTIONS
                        .requestMatchers(new AntPathRequestMatcher("/**", "OPTIONS")).permitAll()
                        .requestMatchers(
                                new AntPathRequestMatcher("/api/auth/register"),
                                new AntPathRequestMatcher("/api/auth/login"),
                                new AntPathRequestMatcher("/api/auth/resend-otp"),
                                new AntPathRequestMatcher("/api/auth/verify-otp"),
                                new AntPathRequestMatcher("/api/auth/forgot-password"),
                                new AntPathRequestMatcher("/api/auth/verify-reset-otp"),
                                new AntPathRequestMatcher("/api/auth/login-user-reset-password"),
                                new AntPathRequestMatcher("/api/auth/reset-forgotten-password")
                        ).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/logout")).authenticated()
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/user/**")).authenticated()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .cors()
                .and()
                .httpBasic();
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // Explicitly allow frontend origins, including the server itself if needed
        corsConfiguration.addAllowedOrigin("http://192.168.70.122:8080"); // Server as an allowed origin
        corsConfiguration.addAllowedOrigin("http://localhost:3000"); // Common frontend origin
        corsConfiguration.addAllowedOrigin("https://fd31-94-207-11-92.ngrok-free.app"); // If still relevant

        // Allow necessary HTTP methods
        corsConfiguration.addAllowedMethod(HttpMethod.GET);
        corsConfiguration.addAllowedMethod(HttpMethod.POST);
        corsConfiguration.addAllowedMethod(HttpMethod.PUT);
        corsConfiguration.addAllowedMethod(HttpMethod.DELETE);
        corsConfiguration.addAllowedMethod(HttpMethod.OPTIONS);

        // Allow all headers
        corsConfiguration.addAllowedHeader("*");

        // Set to true if your frontend sends credentials (e.g., cookies or Authorization headers)
        corsConfiguration.setAllowCredentials(false); // Change to true if credentials are needed

        // Cache pre-flight requests for 1 hour
        corsConfiguration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}