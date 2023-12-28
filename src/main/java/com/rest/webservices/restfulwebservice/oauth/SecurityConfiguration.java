package com.rest.webservices.restfulwebservice.oauth;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private final KeycloakLogoutHandler keycloakLogoutHandler;

    public SecurityConfiguration(KeycloakLogoutHandler keycloakLogoutHandler) {
        this.keycloakLogoutHandler = keycloakLogoutHandler;
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    //http.oauth2Login(Customizer.withDefaults())
//        .logout(Customizer.withDefaults())
//            .logout((logout) -> logout.addLogoutHandler(keycloakLogoutHandler))
//            .logout(logout -> logout.logoutSuccessUrl("/"));
//@Order(1)

    @Bean
    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, MvcRequestMatcher.Builder mvc) throws Exception {
//        httpSecurity
//                .authorizeHttpRequests(registry -> registry
//                        .requestMatchers(mvc.pattern("/authenticate")).permitAll()
//                        .requestMatchers(new AntPathRequestMatcher("/h2-console/*")).permitAll() // h2-console is a servlet and NOT recommended for a production
////                        .requestMatchers(HttpMethod.OPTIONS, String.valueOf(mvc.pattern("/users/**"))).hasRole("USER")
//                        .anyRequest().authenticated()
//                )
//                .csrf(AbstractHttpConfigurer::disable)
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .httpBasic(withDefaults())
//                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
//                .oauth2ResourceServer(oauth2Configurer ->
//                        oauth2Configurer.jwt(
//                                jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(
//                                        jwt -> {
//                                            Map<String, Collection<String>> realmAccess = jwt.getClaim("realm_access");
//                                            Collection<String> roles = realmAccess.get("roles");
//                                            var grantedAuthorities = roles.stream()
//                                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
//                                                    .toList();
//                                            return new JwtAuthenticationToken(jwt, grantedAuthorities);
//                                        })))
//        ;
//
//        return httpSecurity.build();
//    }
//    @Bean
//    public CorsConfigurationSource corsConfig(){
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**")
//                        .allowedOrigins("http://localhost:4200")
//                        .allowedMethods(HttpMethod.GET.name(), HttpMethod.POST.name(), HttpMethod.PUT.name(), HttpMethod.DELETE.name(), HttpMethod.OPTIONS.name())
//                        .allowedHeaders(HttpHeaders.CONTENT_TYPE, HttpHeaders.AUTHORIZATION)
//                        .allowCredentials(true);
//            }
//        };
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(List.of("http://localhost:4200","http://localhost:4200/","http://localhost:9090"));
//
//        // tried this too but without any luck.
//        // configuration.setAllowedOrigins(Arrays.asList("localhost:4200"));
//
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/users/*", configuration);
//        source.registerCorsConfiguration("/authenticate", configuration);
//        return source;
//    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().
                requestMatchers(new AntPathRequestMatcher("/h2-console/**"));
//                .requestMatchers(new AntPathRequestMatcher( "/favicon.ico"))
//                .requestMatchers(new AntPathRequestMatcher( "/css/**"))
//                .requestMatchers(new AntPathRequestMatcher( "/js/**"))
//                .requestMatchers(new AntPathRequestMatcher( "/img/**"))
//                .requestMatchers(new AntPathRequestMatcher( "/lib/**"));

    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {

       return http
               .csrf(AbstractHttpConfigurer::disable)
//               .csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/**")))
//               .cors(cors -> cors.configurationSource(corsConfig()))
               .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers(mvcMatcherBuilder.pattern("/authenticate"),PathRequest.toH2Console()).permitAll()
//                        .requestMatchers(mvcMatcherBuilder.pattern(API_URL_PATTERN)).permitAll()
//                        .requestMatchers().permitAll() // h2-console is a servlet and NOT recommended for a production
//                        .requestMatchers(new AntPathRequestMatcher("/users/*"))
//                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector,"/authenticate")).permitAll()
//                        .requestMatchers(HttpMethod.OPTIONS, "/users/*").permitAll()
                        .requestMatchers(new MvcRequestMatcher(introspector, "/users/*"))//.permitAll()

//                        .requestMatchers(mvcMatcherBuilder.pattern("/users/*"))
                        .hasRole("USER")
                        .anyRequest()
                        .authenticated()
                )

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(Customizer.withDefaults())
                .logout(Customizer.withDefaults())
                .logout((logout) -> logout.addLogoutHandler(keycloakLogoutHandler))
                .logout(logout -> logout.logoutSuccessUrl("http://localhost:4200"))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .httpBasic(withDefaults())
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .build();

    }


//public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
//    http.authorizeRequests()
//            .requestMatchers(new AntPathRequestMatcher("/console/**")).permitAll()
//            .requestMatchers(new AntPathRequestMatcher("/"))
//            .permitAll()
//            .anyRequest()
//            .authenticated();
//http.oauth2Login(Customizer.withDefaults())
//        .logout(Customizer.withDefaults())
//            .logout((logout) -> logout.addLogoutHandler(keycloakLogoutHandler))
//            .logout(logout -> logout.logoutSuccessUrl("/"));
//    return http.build();
//}
//
//    @Order(2)
//    @Bean
//    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//
//                .requestMatchers(new AntPathRequestMatcher("/customers*"))
//                .hasRole("USER")
//                .anyRequest()
//                .authenticated();
//        http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
//        return http.build();
//    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }


}