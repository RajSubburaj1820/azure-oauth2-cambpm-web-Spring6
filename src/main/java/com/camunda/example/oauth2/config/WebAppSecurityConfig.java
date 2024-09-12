package com.camunda.example.oauth2.config;

import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter;
import java.util.Collections;
import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.context.request.RequestContextListener;

/** Used for Azure AD security. */
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
@Configuration
public class WebAppSecurityConfig  {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/public/**").permitAll()
            .anyRequest().authenticated()
        )
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/oauth2/authorization/azure")  // Specify the AAD authorization endpoint
        )
        .logout(logout -> logout
            .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
        );

    return http.build();
  }
  private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
    OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    successHandler.setPostLogoutRedirectUri("{baseUrl}/login");  // Specify your post-logout redirect URI
    return successHandler;
  }
  /*
  @Override
  public void configure(HttpSecurity http) throws Exception {
    // use required configuration form AADWebSecurityAdapter.configure:
    super.configure(http);
    // add custom configuration:
    http.authorizeRequests()
        .antMatchers("/camunda/**")
        .authenticated() // limit these pages to authenticated users (default: /token_details)
        .antMatchers("/**")
        .permitAll(); // allow all other routes.
  }


  @Bean
  public FilterRegistrationBean<ContainerBasedAuthenticationFilter>
      containerBasedAuthenticationFilter() {

    FilterRegistrationBean<ContainerBasedAuthenticationFilter> filterRegistration =
        new FilterRegistrationBean<>();
    filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
    filterRegistration.setInitParameters(
        Collections.singletonMap(
            "authentication-provider",
            SpringSecurityOAuth2AuthenticationProvider.class.getCanonicalName()));
    filterRegistration.setOrder(
        101); // make sure the filter is registered after the Spring Security Filter Chain
    filterRegistration.addUrlPatterns("/camunda/*");
    return filterRegistration;
  }

  @Bean
  @Order(0)
  public RequestContextListener requestContextListener() {
    return new RequestContextListener();
  }

   */
}
