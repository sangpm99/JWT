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
```text
server.port=8081
```

### Tạo các folder tại <code>src/main/java/com/jwt/example/JWTExample</code>: <code>config</code>, <code>controller</code>, <code>models</code>, <code>security</code>, <code>service</code>

###
Tạo file <code>.../controller/HomeController.java</code>:
```text
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
