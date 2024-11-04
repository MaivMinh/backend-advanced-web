package com.foolish.backend.config;

import com.foolish.backend.filters.CsrfTokenFilter;
import com.foolish.backend.filters.JwtValidatorFilter;
import com.foolish.backend.handler.SpaCsrfTokenRequestAttributeHandler;
import com.foolish.backend.security.*;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;
import java.util.List;

@Configuration
@AllArgsConstructor
public class ProjectSecurityConfig {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.csrf(config -> config
            .ignoringRequestMatchers(
                    "/api/v1/auth/**",
                    "/api/v1/public/**")
            .csrfTokenRequestHandler(new SpaCsrfTokenRequestAttributeHandler())
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    );
    http.addFilterAfter(new CsrfTokenFilter(), BasicAuthenticationFilter.class);
    http.addFilterAfter(new JwtValidatorFilter(), ExceptionTranslationFilter.class);
    http.cors(corsConfig -> corsConfig
            .configurationSource(request -> {
              CorsConfiguration config = new CorsConfiguration();
              config.setAllowedOrigins(Collections.singletonList("*")); //Thay thế Origin này sau khi lên Production.
              config.setAllowedMethods(Collections.singletonList("*"));
              config.setAllowCredentials(true);
              config.setAllowedHeaders(Collections.singletonList("*"));
              config.setExposedHeaders(List.of("Authorization"));
              config.setMaxAge(3600L);
              return config;
            }));
    http
            .authorizeHttpRequests(config -> config
                    .requestMatchers(
                            "/api/v1/public/**", "/api/v1/auth/**").permitAll()
                    .requestMatchers("api/v1/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated());
    http.httpBasic(config -> config.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
    http.exceptionHandling(config -> config.accessDeniedHandler(new CustomAccessDeniedHandler()));
    return http.build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  // Cho phép API endpoint phía dưới đi qua Filers chain.
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web.ignoring().requestMatchers(
            "/api/v1/auth/**"
    );
  }

  // Tạo ra một Manager mới để chủ động trong việc tạo JWT Token ở AuthController.
  @Bean
  public AuthenticationManager authenticationManager(OwnUserDetailsService userDetailsService, PasswordEncoder encoder) throws Exception {
    ProdUsernamePwdAuthenticationProvider provider =
            new ProdUsernamePwdAuthenticationProvider(userDetailsService, encoder);
    ProviderManager manager = new ProviderManager(provider);
    manager.setEraseCredentialsAfterAuthentication(false);
    return manager;
  }
}
