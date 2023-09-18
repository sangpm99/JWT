# JWT Example
Dự án sử dụng Jwt Authentication với Spring Boot 3.1 cho chức năng đăng nhập

### Clone project
```bash
git clone https://github.com/sangpm99/JWT.git
```

## Tạo mới project
### Tạo project với maven
Tạo project bằng cách sử dụng <code>Spring Initializr</code>, <code>Spring Assistant</code> hoặc truy cập [start.spring.io](https://start.spring.io/)
- <code>Name: JWTExample</code>
- <code>Language: Java</code>
- <code>Type: maven</code>
- <code>Group: com.example</code>
- <code>Artifact: JWTExample</code>
- <code>Package name: com.example.jwtexample</code>
- <code>Packaging: Jar</code>

### Thêm các dependency
Tại file pom.xml thêm các dependence trong mục <code>dependencies</code>
- Web
```text
<dependency>
    <groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

- Security
```text
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

- Lombok
```text
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
```

- JWT
```text
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```
- Login page
```text
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
    <version>3.1.3</version>
</dependency>
```

### Cài đặt cổng (bỏ qua nếu dùng cổng mặc định là 8080)
Tại file <code>src/main/resources/application.properties</code>:
```properties
server.port=8081
```

### Tạo các folder tại <code>src/main/java/com/jwt/example/JWTExample</code>: <code>config</code>, <code>controller</code>, <code>models</code>, <code>security</code>, <code>service</code>
### Tạo file controller

Các địa chỉ điều hướng sẽ nằm tại phần này
<br>
Tạo file <code>.../controller/HomeController.java</code>:
```java
package com.jwt.example.JWTExample.controller;

import com.jwt.example.JWTExample.models.User;
import com.jwt.example.JWTExample.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/home")
public class HomeController {
    @Autowired
    private UserService userService;

    // http://localhost:8081/home/users
    @RequestMapping("/users")
    public List<User> getUser() {
        System.out.println("getting users");
        return userService.getUser();
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login() {
        return "login";
    }

    @GetMapping("/current-user")
    public String getLoggedInUser(Principal principal) {
        return principal.getName();
    }
}
```

### Tạo model User
Tạo file <code>.../models/User.java</code>:
```java
package com.jwt.example.JWTExample.models;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class User {
    private String userId;
    private String name;
    private String email;
}
```

### Tạo Service
Tạo các User <code>UserService()</code>, đây sẽ là dữ liệu người dùng, hiện tại khởi tạo thủ công, có thể thay bằng truy vấn database nếu có
<br>
Tạo file <code>.../service/UserService.java</code>:
```java
package com.jwt.example.JWTExample.service;

import org.springframework.stereotype.Service;
import com.jwt.example.JWTExample.models.User;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {
    private List<User> store = new ArrayList<>();

    public UserService() {
        store.add(new User(UUID.randomUUID().toString(), "User Name 1", "username1@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 2", "username2@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 3", "username3@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(), "User Name 4", "username4@gmail.com"));
    }

    public List<User> getUser() {
        return store;
    }
}
```

### Tạo AppConfig
Tạo 2 người dùng với với quyền admin <code>userDetailsService()</code> để đăng nhập
<br>
Lúc này có thể truy cập trình duyệt http://localhost:8081 với <code>username</code> và <code>password</code> được khởi tạo bên dưới
<br>
Tạo file <code>.../config/AppConfig.java</code>:
```java
package com.jwt.example.JWTExample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class AppConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder().username("harsh").password(passwordEncoder().encode("abc")).roles("ADMIN").build();
        UserDetails user1 = User.builder().username("admin").password(passwordEncoder().encode("abc")).roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user, user1);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}

```

### Tạo JwtAuthenticationEntryPoint
Lớp này sẽ ngăn sẽ ngăn truy cập và đưa ra ngoại lệ nếu người dùng chưa xác thực mà thao tác các tác vụ yêu cầu xác thực (lưu ý từ phần này trở đi không test trên trình duyệt được nữa, dùng Postman để test)
<br>
Tạo file <code>.../security/JwtAuthenticationEntryPoint.java</code>:
```java
package com.jwt.example.JWTExample.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println("Access Denined !! " + authException.getMessage());
    }
}

```

### Tạo file config JWT
Lớp này sẽ thực hiện việc định nghĩa các chữ ký, tạo khóa, ...
Tạo file <code>.../security/JwtHelper.java</code>:
```java
package com.jwt.example.JWTExample.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

@Component
public class JwtHelper {

    // requirement
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60; //  = 5 hours

    // secret key
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}

```

### Tạo JwtAuthenticationFilter
Lớp này xử lý 5 yêu cầu quan trọng
- Nhận Token từ request
- Xác thực Token
- Nhận tên người dùng từ Token
- Tải người dùng được liên kết từ Token
- Cài đặt xác thực
<br>
Tạo file <code>.../security/JwtAuthenticationFilter.java</code>:
```java
package com.jwt.example.JWTExample.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
    @Autowired
    private JwtHelper jwtHelper;


    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestHeader = request.getHeader("Authorization");
        //Bearer 2352345235sdfrsfgsdfsdf
        logger.info(" Header :  {}", requestHeader);
        String username = null;
        String token = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
            //looking good
            token = requestHeader.substring(7);
            try {
                username = this.jwtHelper.getUsernameFromToken(token);

            } catch (IllegalArgumentException e) {
                logger.info("Illegal Argument while fetching the username !!");
                e.printStackTrace();
            } catch (ExpiredJwtException e) {
                logger.info("Given jwt token is expired !!");
                e.printStackTrace();
            } catch (MalformedJwtException e) {
                logger.info("Some changed has done in token !! Invalid Token");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();

            }
        } else {
            logger.info("Invalid Header Value !! ");
        }
        //
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //fetch user detail from username
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            if (validateToken) {

                //set the authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                logger.info("Validation fails !!");
            }
        }
        filterChain.doFilter(request, response);
    }
}

```

### Tạo SecurityConfig
Tạo file <code>.../config/SecurityConfig.java</code>:
```java
package com.jwt.example.JWTExample.config;

import com.jwt.example.JWTExample.security.JwtAuthenticationEntryPoint;
import com.jwt.example.JWTExample.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Autowired
    private JwtAuthenticationEntryPoint point;
    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable())
                .authorizeRequests().
                requestMatchers("/test").authenticated().requestMatchers("/auth/login").permitAll()
                .anyRequest()
                .authenticated()
                .and().exceptionHandling(ex -> ex.authenticationEntryPoint(point))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

### Tạo JwtRequest
Tạo file <code>.../models/JwtRequest.java</code>:
```java
package com.jwt.example.JWTExample.models;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class JwtRequest {
    private String email;
    private String password;
}

```

### Tạo JwtResponse
Tạo file <code>.../models/JwtResponse.java</code>:
```java
package com.jwt.example.JWTExample.models;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class JwtResponse {
    private String jwtToken;
    private String username;
}

```

### Tạo controller AuthController
Tạo file <code>.../controller/AuthController.java</code>:
```java
package com.jwt.example.JWTExample.controller;

import com.jwt.example.JWTExample.models.JwtRequest;
import com.jwt.example.JWTExample.models.JwtResponse;
import com.jwt.example.JWTExample.security.JwtHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager manager;


    @Autowired
    private JwtHelper helper;

    private Logger logger = LoggerFactory.getLogger(AuthController.class);


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {

        this.doAuthenticate(request.getEmail(), request.getPassword());


        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = this.helper.generateToken(userDetails);

        JwtResponse response = JwtResponse.builder()
                .jwtToken(token)
                .username(userDetails.getUsername()).build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void doAuthenticate(String email, String password) {

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            manager.authenticate(authentication);


        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(" Invalid Username or Password  !!");
        }

    }

    @ExceptionHandler(BadCredentialsException.class)
    public String exceptionHandler() {
        return "Credentials Invalid !!";
    }
}

```

# Test trên Postman:
Lưu ý:
- Các jwtToken ví dụ dưới đây chỉ đúng với bài mẫu, hãy thay thế bằng jwtToken của bạn
- Địa chỉ có thể khác, phụ thuộc vào file <code>controller</code> và <code>application.properties</code> bạn đặt
- Có thể test trên trình duyệt nhưng phải ẩn file <code>JwtAuthenticationEntryPoint</code> và <code>SecurityConfig</code>, tuy nhiên không khuyến nghị
## Test chức năng đăng nhập
Địa chỉ: http://localhost:8081/auth/login
<br>
Phương thức: <code>POST</code>
<br>
Body: <code>raw</code>, <code>JSON</code>:
<br>
```json
{
    "email": "admin",
    "password": "abc"
}
```
Kết quả:
- jwtToken sẽ chỉ khả dụng trong vòng 5h (xem file <code>JwtHelper.java</code>) kể từ khi được tạo
```json
{
  "jwtToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY5NTAwOTA2MCwiZXhwIjoxNjk1MDI3MDYwfQ.qxHkYWVaqyYyyb7ruhYCUx1vNcis3PREA-paLPgaAAhbPskAjiGKt9HTVXXIorhPItUmzAzLjfzRR74arsAUhw",
  "username": "admin"
}
```

## Test chức năng lấy tất cả người dùng
Địa chỉ: http://localhost:8081/home/users
<br>
Phương thức: <code>GET</code>
<br>
Header:
- Key: <code>Authorization</code>
- Value: <code>Bearer</code> eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY5NTAwOTA2MCwiZXhwIjoxNjk1MDI3MDYwfQ.qxHkYWVaqyYyyb7ruhYCUx1vNcis3PREA-paLPgaAAhbPskAjiGKt9HTVXXIorhPItUmzAzLjfzRR74arsAUhw
<br>
Bearer token hay gọi là Bearer authentication chính là token authentication. Là một HTTP authentication scheme liên quan đến các token bảo mật.
<br />
<table>
    <tr>
        <th>Key</th>
        <th>Value</th>
    </tr>
    <tr>
        <td>Authorization</td>
        <td>Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY5NTAwOTA2MCwiZXhwIjoxNjk1MDI3MDYwfQ.qxHkYWVaqyYyyb7ruhYCUx1vNcis3PREA-paLPgaAAhbPskAjiGKt9HTVXXIorhPItUmzAzLjfzRR74arsAUhw</td>
    </tr>
</table>

Kết quả:
```json
[
  {
    "userId": "815a6fee-9478-494f-be1b-56742e96ffb5",
    "name": "User Name 1",
    "email": "username1@gmail.com"
  },
  {
    "userId": "6ffaae38-8c74-4646-ba62-7638ee0166a4",
    "name": "User Name 2",
    "email": "username2@gmail.com"
  },
  {
    "userId": "1cadb419-a6d3-4538-abd9-2fa9e205e28d",
    "name": "User Name 3",
    "email": "username3@gmail.com"
  },
  {
    "userId": "611b7460-5077-4084-8d99-a9cf15429a73",
    "name": "User Name 4",
    "email": "username4@gmail.com"
  }
]
```

## Test chức năng lấy tên người đăng nhập
Địa chỉ: http://localhost:8081/home/current-user
<br>
Phương thức: <code>GET</code>
<br>
Header:
- Key: <code>Authorization</code>
- Value: <code>Bearer</code> eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY5NTAwOTA2MCwiZXhwIjoxNjk1MDI3MDYwfQ.qxHkYWVaqyYyyb7ruhYCUx1vNcis3PREA-paLPgaAAhbPskAjiGKt9HTVXXIorhPItUmzAzLjfzRR74arsAUhw
<br>

<table>
    <tr>
        <th>Key</th>
        <th>Value</th>
    </tr>
    <tr>
        <td>Authorization</td>
        <td>Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTY5NTAwOTA2MCwiZXhwIjoxNjk1MDI3MDYwfQ.qxHkYWVaqyYyyb7ruhYCUx1vNcis3PREA-paLPgaAAhbPskAjiGKt9HTVXXIorhPItUmzAzLjfzRR74arsAUhw</td>
    </tr>
</table>

Kết quả:
```text
admin
```