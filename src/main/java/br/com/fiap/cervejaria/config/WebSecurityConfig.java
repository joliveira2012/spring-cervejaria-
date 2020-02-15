package br.com.fiap.cervejaria.config;

import br.com.fiap.cervejaria.security.JwtAuthenticationEntryPoint;
import br.com.fiap.cervejaria.security.JwtRequestFilter;
import br.com.fiap.cervejaria.security.JwtUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtUserDetailsService jwtUserDetailsService;
    private final JwtRequestFilter jwtRequestFilter;
    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                             JwtUserDetailsService jwtUserDetailsService,
                             JwtRequestFilter jwtRequestFilter,
                             PasswordEncoder passwordEncoder) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtRequestFilter =jwtRequestFilter;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .authorizeRequests().antMatchers("/users/**").permitAll().
                anyRequest().authenticated().and().exceptionHandling().
                authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement().
                sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }



    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("{noop}adminsenha").roles("ADMIN", "USER")
            .and()
                .withUser("user").password("{noop}usersenha").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/cervejas").hasRole("ADMIN")
                .and()
                .csrf().disable()
                .formLogin().disable();
    }*/
}
