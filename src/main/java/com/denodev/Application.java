package com.denodev;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Arnaud DENOYELLE
 */
@RestController
@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class);
  }

  @RequestMapping(value = "/upload-file", method = RequestMethod.POST)
  @ResponseBody
  public String uploadFile(@RequestParam("file") MultipartFile file) {
    return "Successfully received file "+file.getOriginalFilename();
  }

  @Configuration
  @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
  protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
      http
          .authorizeRequests()
          .antMatchers("/", "/**/*.html", "login").permitAll()
          .anyRequest().authenticated()
          .and()
            .formLogin()
            .successHandler(successHandler())
            .failureHandler(failureHandler())
          .and()
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler())
            .authenticationEntryPoint(authenticationEntryPoint())
          .and()

          //1 : Uncomment to activate csrf protection
          .csrf()
          .csrfTokenRepository(csrfTokenRepository())
          .and()
          .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)

          //2 : Uncomment to disable csrf protection
          //.csrf().disable()
      ;
    }

    /**
     * Return HTTP 200 on authentication success instead of redirecting to a page.
     */
    private AuthenticationSuccessHandler successHandler() {
      return new AuthenticationSuccessHandler() {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
          httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        }
      };
    }

    /**
     * Return HTTP 401 on authentication failure instead of redirecting to a page.
     */
    private AuthenticationFailureHandler failureHandler() {
      return new AuthenticationFailureHandler() {
        @Override
        public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
          httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          httpServletResponse.getWriter().write(e.getMessage());
        }
      };
    }

    /**
     * Return HTTP 403 on "access denied" instead of redirecting to a page.
     */
    private AccessDeniedHandler accessDeniedHandler() {
      return new AccessDeniedHandler() {
        @Override
        public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
          httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
          httpServletResponse.getWriter().write(e.getMessage());
        }
      };
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
      return new AuthenticationEntryPoint() {
        @Override
        public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
          httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          httpServletResponse.getWriter().write(e.getMessage());
        }
      };
    }

    /**
     * (Copy/pasted from
     *   <a href="https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii">
     *   https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii
     *   </a> )
     * <p/>
     *
     * Spring Security’s has built-in CSRF protection. All it wants is a token sent to it in a header called “X-CSRF”.
     * <p/>
     *
     * To get it to the client we could render it using a dynamic HTML page on the server, or expose it via a custom
     * endpoint, or else we could send it as a cookie.
     * <p/>
     *
     * The last choice is the best because Angular has built in support for CSRF (which it calls “XSRF”) based on cookies.
     * <p/>
     *
     * So all we need on the server is a custom filter that will send the cookie. Angular wants the cookie name to be
     * “XSRF-TOKEN” and Spring Security provides it as a request attribute, so we just need to transfer the value from
     * a request attribute to a cookie:
     * <p/>
     *
     */
    private Filter csrfHeaderFilter() {
      return new OncePerRequestFilter() {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
          CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
          if (csrf != null) {
            Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
            String token = csrf.getToken();
            if (cookie == null || token != null && !token.equals(cookie.getValue())) {
              cookie = new Cookie("XSRF-TOKEN", token);
              cookie.setPath("/");
              response.addCookie(cookie);
            }
          }
          filterChain.doFilter(request, response);
        }
      };
    }

    private CsrfTokenRepository csrfTokenRepository() {
      HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
      repository.setHeaderName("X-XSRF-TOKEN");
      return repository;
    }
  }



}
