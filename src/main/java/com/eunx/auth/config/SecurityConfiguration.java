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

import java.util.Arrays;

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
                        // Permit pre-flight OPTIONS requests
                        .requestMatchers(new AntPathRequestMatcher("/**", "OPTIONS")).permitAll()
                        // Permit these endpoints for all
                        .requestMatchers(
                                new AntPathRequestMatcher("/api/auth/register"),
                                new AntPathRequestMatcher("/api/auth/login"),
                                new AntPathRequestMatcher("/api/auth/resend-otp"),
                                new AntPathRequestMatcher("/api/auth/verify-otp"),
                                new AntPathRequestMatcher("/api/auth/forgot-password"),
                                new AntPathRequestMatcher("/api/auth/verify-reset-otp"),
                                new AntPathRequestMatcher("/api/auth/login-user-reset-password"),
                                new AntPathRequestMatcher("/api/auth/reset-forgotten-password"),
                                new AntPathRequestMatcher("/api/auth/verify-2fa"),
                                new AntPathRequestMatcher("/api/auth/enable-2fa"),
                                new AntPathRequestMatcher("/api/auth/disable-2fa"),
                                new AntPathRequestMatcher("/api/auth/refresh-token")


                        ).permitAll()

                        // Logout endpoint requires authentication
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/logout")).authenticated()
                        // Any user-specific endpoints require authentication
                        .requestMatchers(new AntPathRequestMatcher("/api/auth/user/**")).authenticated()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .cors().and() // Enable CORS with our custom configuration
                .httpBasic();
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        // Allow all origins
        corsConfiguration.addAllowedOriginPattern("*");
        // Allow specific HTTP methods
        corsConfiguration.setAllowedMethods(Arrays.asList(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name()
        ));
        // Allow all headers
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        // Credentials are not allowed with wildcard origins
        corsConfiguration.setAllowCredentials(false);
        // Cache the pre-flight response for 1 hour
        corsConfiguration.setMaxAge(3600L);
        // Expose headers for debugging if necessary
        corsConfiguration.setExposedHeaders(Arrays.asList("Access-Control-Allow-Origin", "Access-Control-Allow-Methods"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}
