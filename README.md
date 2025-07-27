# Spring Boot JWT Authentication with OAuth2 Resource Server

This guide provides step-by-step instructions for implementing JWT authentication using OAuth2 Resource Server in Spring Boot applications, supporting both Spring MVC and Spring WebFlux.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Implementation](#implementation)
  - [Spring MVC](#spring-mvc)
  - [Spring WebFlux](#spring-webflux)
- [Role-Based Authorization](#role-based-authorization)
- [Usage Examples](#usage-examples)
- [Security Considerations](#security-considerations)

## Prerequisites

- Spring Boot 3.x
- Java 17 or higher
- Maven or Gradle

## Dependencies

Add the following dependencies to your `pom.xml`:

```xml
<dependencies>
    <!-- Spring Boot Starter Web (for MVC) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- OR Spring Boot Starter WebFlux (for WebFlux) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-webflux</artifactId>
    </dependency>
    
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- OAuth2 Resource Server -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    
    <!-- JWT Support -->
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
</dependencies>
```

## Configuration

### Application Properties

Add the following properties to your `application.properties` or `application.yml`:

```properties
# JWT Configuration
jwt.secret=Z2V0LWFjdHVhbC1rZXktZnJvbS1wcm9wcy1maWxlLW9yLWVudi1zZWN1cmVseQ==
spring.security.oauth2.resourceserver.jwt.secret=Z2V0LWFjdHVhbC1rZXktZnJvbS1wcm9wcy1maWxlLW9yLWVudi1zZWN1cmVseQ==
```

## Implementation

### Spring MVC

#### 1. JWT Decoder Configuration

```java
package com.example.auth_service.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;

@Configuration
public class JwtDecoderConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        return NimbusJwtDecoder.withSecretKey(key).build();
    }
}
```

#### 2. Cookie Bearer Token Resolver

```java
package com.example.auth_service.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;

@Component
public class CookieBearerTokenResolver implements BearerTokenResolver {

    @Override
    public String resolve(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if ("Access-Token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
```

#### 3. Security Configuration

```java
package com.example.auth_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private CookieBearerTokenResolver cookieBearerTokenResolver;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .bearerTokenResolver(cookieBearerTokenResolver)
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return jwtAuthenticationConverter;
    }
}
```

### Spring WebFlux

#### 1. JWT Decoder Configuration

```java
package com.example.auth_service.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;

@Configuration
public class JwtDecoderConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        return NimbusJwtDecoder.withSecretKey(key).build();
    }
}
```

#### 2. Cookie Token Authentication Converter

```java
package com.example.api_gateway.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CookieTokenAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst("Access-Token"))
                .map(cookie -> new BearerTokenAuthenticationToken(cookie.getValue()));
    }
}
```

#### 3. Security Configuration

```java
package com.example.auth_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Autowired
    private CookieTokenAuthenticationConverter cookieTokenAuthenticationConverter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(authz -> authz
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .bearerTokenConverter(cookieTokenAuthenticationConverter)
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return jwtAuthenticationConverter;
    }
}
```

## Role-Based Authorization

The configuration above automatically extracts roles from the JWT's `roles` claim and converts them to Spring Security authorities. The JWT should contain a `roles` claim with an array of role strings:

```json
{
  "sub": "user123@example.com",
  "roles": ["ROLE_ADMIN", "ROLE_USER"],
  "exp": 1640995200
}
```

### Using @PreAuthorize Annotations

With the configuration in place, you can now use `@PreAuthorize` annotations directly in your controllers:

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminOnly() {
        return ResponseEntity.ok("Admin access granted");
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> userOnly() {
        return ResponseEntity.ok("User access granted");
    }

    @GetMapping("/both")
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    public ResponseEntity<String> bothRoles() {
        return ResponseEntity.ok("Access granted for both roles");
    }
}
```

## Usage Examples

### Controller Example

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserProfile> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        String userId = jwt.getSubject();
        // Your business logic here
        return ResponseEntity.ok(new UserProfile(userId, "John Doe"));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        // Admin-only operation
        return ResponseEntity.noContent().build();
    }
}
```

### Service Example

```java
@Service
public class UserService {

    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.name")
    public UserProfile getUserProfile(String userId) {
        // Users can only access their own profile, admins can access any
        return userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException(userId));
    }
}
```

## Security Considerations

1. **JWT Secret**: Always use a strong, randomly generated secret key
2. **Token Expiration**: Set appropriate expiration times for JWT tokens
3. **HTTPS**: Always use HTTPS in production
4. **Token Storage**: Store tokens securely (HttpOnly cookies for web applications)
5. **Role Validation**: Always validate roles on both client and server side
6. **Token Refresh**: Implement token refresh mechanisms for long-lived sessions

## Testing

### Prerequisites

Before testing, ensure you have the following services running:
- **auth-service** (Authentication service) on port 8082
- **api-gateway** on port 8080 (optional, for routing through gateway)
- **service-registry** (Service Discovery service)

### Step 1: Register/Login to Get JWT Tokens

#### Option 1: Direct Auth Service
```bash
# Register a new user
curl -X POST http://localhost:8082/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }' \
  -c cookies.txt

# Login with existing user
curl -X POST http://localhost:8082/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }' \
  -c cookies.txt
```

#### Option 2: Through API Gateway
```bash
# Register a new user through gateway
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }' \
  -c cookies.txt

# Login through gateway
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }' \
  -c cookies.txt
```

**Note**: After successful registration/login, you will receive both `Access-Token` and `Refresh-Token` as HttpOnly cookies.

### Step 2: Test Protected Endpoints

Once you have the JWT tokens, you can test your protected services:

```bash
# Test with cookies (recommended)
curl -b cookies.txt http://localhost:8080/api/users/profile

# Test with Bearer token (extract from cookie if needed)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8080/api/users/profile

# Test other services (order, payment, store, etc.)
curl -b cookies.txt http://localhost:8080/api/orders
curl -b cookies.txt http://localhost:8080/api/payments
curl -b cookies.txt http://localhost:8080/api/store/products
```

### Testing with Postman

1. **Register/Login**: Send POST request to `http://localhost:8082/auth/register` or `http://localhost:8080/auth/register`
2. **Use Cookies**: Postman will automatically handle the HttpOnly cookies from the response
3. **Test Protected Endpoints**: Make requests to your protected services - cookies will be sent automatically

### Testing with Browser

1. **Register/Login**: Navigate to your auth service endpoints
2. **Automatic Cookie Handling**: Browsers automatically send HttpOnly cookies with requests
3. **Test Your Services**: Call your protected endpoints directly

## Troubleshooting

### Common Issues

1. **403 Forbidden**: Check if the JWT contains the required roles
2. **401 Unauthorized**: Verify the JWT signature and expiration
3. **Role not found**: Ensure the JWT contains the `roles` claim with the correct format

### Debug Mode

Enable debug logging for security:

```properties
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.oauth2=DEBUG
```

## Additional Resources

- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [OAuth2 Resource Server Documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)
- [JWT.io](https://jwt.io/) - JWT Debugger and Documentation 
