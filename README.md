# Spring-Security

# 🔵 Overview of Spring Security

**Spring Security** is a **powerful and highly customizable framework** for **authentication, authorization, and security management** in Java applications, especially Spring-based applications. It provides a complete **security infrastructure** for web and method-level security.

---

## 🟢 1. Purpose of Spring Security

1. **Authentication** – Verifying who the user is (login).
2. **Authorization** – Checking if the user has access to specific resources or actions (roles/permissions).
3. **Protection** – Guarding against common security threats like:

   * CSRF (Cross-Site Request Forgery)
   * Session Fixation
   * Clickjacking
   * HTTP header injection
   * Brute force attacks
4. **Extensibility** – Can integrate with **LDAP, OAuth2, JWT, in-memory, and database-based authentication**.

---

## 🟡 2. Key Concepts

* **Authentication** – Process of validating credentials.
* **Authorization (Access Control)** – Granting/denying access to endpoints based on roles/authorities.
* **Security Context** – Holds details about the authenticated user (`SecurityContextHolder`).
* **Filter Chain** – All requests go through a **chain of filters** before reaching the controller.
* **UserDetailsService** – Interface to load user-specific data.
* **PasswordEncoder** – Interface to encode and match passwords securely.

---

## 🟠 3. Components

| Component                | Role                                                                                   |
| ------------------------ | -------------------------------------------------------------------------------------- |
| `FilterChainProxy`       | Delegates requests to the correct security filters.                                    |
| `Security Filter Chain`  | Collection of filters handling authentication, authorization, exception handling, etc. |
| `AuthenticationManager`  | Entry point for authentication; delegates to providers.                                |
| `AuthenticationProvider` | Implements authentication logic (e.g., database, in-memory).                           |
| `UserDetailsService`     | Loads user data from DB or memory.                                                     |
| `PasswordEncoder`        | Encodes and validates passwords.                                                       |
| `SecurityContextHolder`  | Stores the authenticated user for the current thread.                                  |

---

## 🔴 4. How It Works (High-Level Flow)

```
Client → Server (Tomcat) → Servlet Filter Chain → FilterChainProxy → Security Filters →
AuthenticationManager → AuthenticationProvider → UserDetailsService + PasswordEncoder →
SecurityContextHolder → DispatcherServlet → Controller → Response
```

* **Step 1:** Client sends login request.
* **Step 2:** Filters intercept request; UsernamePasswordAuthenticationFilter extracts credentials.
* **Step 3:** AuthenticationManager delegates to AuthenticationProvider.
* **Step 4:** UserDetailsService loads user, PasswordEncoder matches password.
* **Step 5:** Authenticated object stored in SecurityContextHolder.
* **Step 6:** Controller can access authenticated user.

---

## 🟢 5. Advantages of Spring Security

* Highly **customizable and extensible**.
* Provides **built-in protection** for common web vulnerabilities.
* Can secure **web applications, REST APIs, and microservices**.
* Integrates with **OAuth2, JWT, LDAP, and SSO** easily.
* Follows **best practices** for password storage and session management.

---

## 🟡 6. Common Use Cases

* Login and registration systems.
* Role-based access control (RBAC).
* JWT-based stateless authentication for APIs.
* OAuth2 and SSO (Single Sign-On) integration.
* Protecting sensitive endpoints in microservices.

---

# 🔵 ① Spring Security Authentication Flow

When a client hits `/login`, Spring Security **does not immediately hit your controller**. Instead, the framework intercepts the request **at the filter layer**, checks credentials, authenticates, stores the user in context, and only then passes the request to your controller.

**High-level flow:**

```
Client (/login)
        ↓
Tomcat
        ↓
Servlet Filter Chain
        ↓
FilterChainProxy
        ↓
Security Filter Chain
        ↓
UsernamePasswordAuthenticationFilter
        ↓
AuthenticationManager (ProviderManager)
        ↓
AuthenticationProvider (DaoAuthenticationProvider)
        ↓
UserDetailsService → Fetch User
        ↓
PasswordEncoder → Match Password
        ↓
Authenticated Token Created
        ↓
SecurityContextHolder (ThreadLocal Storage)
        ↓
DispatcherServlet
        ↓
Controller
        ↓
Response

```

---

# 🟢 ② Step 1 – Client Sends Login Request

When the user submits a login form:

```
POST /login
username=rabbani
password=1234
```

* Tomcat receives the request.
* The request enters the **Servlet Filter Chain**, which is a standard chain of filters applied to every incoming request.
* **Why filters?** Security must happen **before your controller logic**. Filters intercept requests at the container level, allowing pre-processing and post-processing.

---

# 🟣 ③ Step 2 – FilterChainProxy & Security Filter Chain

`FilterChainProxy` is **the main entry point for Spring Security**.

* It acts as a **delegator**, sending the request to the correct `SecurityFilterChain` based on URL patterns.
* For `/login`, the chain typically includes:

```
SecurityContextPersistenceFilter → UsernamePasswordAuthenticationFilter → 
ConcurrentSessionFilter → ExceptionTranslationFilter → FilterSecurityInterceptor
```

**Key Points:**

* **SecurityContextPersistenceFilter:** Loads the `SecurityContext` (authentication info) from session or other storage.
* **UsernamePasswordAuthenticationFilter:** Extracts username/password and triggers authentication.
* **ExceptionTranslationFilter:** Converts Spring Security exceptions into proper HTTP responses (401, 403).
* **FilterSecurityInterceptor:** Checks authorization for protected endpoints.

**Diagram:**

```
FilterChainProxy
        ↓
Security Filter Chain
   ┌──────────────┐
   │ Multiple     │
   │ Filters      │
   └──────────────┘
```

---

# 🟡 ④ Step 3 – UsernamePasswordAuthenticationFilter

This filter is **responsible for login form authentication**.

* Extracts `username` and `password`.
* Creates an **Authentication request token**:

```java
Authentication authRequest = 
    new UsernamePasswordAuthenticationToken(username, password);
```

* Delegates authentication to **AuthenticationManager**.

**Important:** At this stage:

```
authenticated = false
```

The token only represents a **login attempt**, not a verified user.

---

# 🟠 ⑤ Step 4 – AuthenticationManager (ProviderManager)

Spring’s `AuthenticationManager` is implemented by **ProviderManager**:

* Holds a list of `AuthenticationProvider`s.
* Loops through each provider to check `supports(authentication.getClass())`.
* Delegates authentication to the first provider that supports the token.

**Why this design?**

* Allows multiple authentication mechanisms (DB, in-memory, OAuth2, JWT, LDAP) to coexist.
* Follows **Strategy Pattern**: each provider is a separate strategy.

**Diagram:**

```
ProviderManager
    ├─ DaoAuthenticationProvider
    ├─ InMemoryAuthenticationProvider
    ├─ OAuth2AuthenticationProvider
```

---

# 🔵 ⑥ Step 5 – DaoAuthenticationProvider

Used for database-backed login:

* Calls `UserDetailsService` to fetch user data.
* Uses `PasswordEncoder` to verify password.
* Returns a fully authenticated `UsernamePasswordAuthenticationToken` with roles and authorities.

**Code Snippet (UserDetailsService):**

```java
UserDetails user = userDetailsService.loadUserByUsername(username);
if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
    throw new BadCredentialsException("Invalid password");
}
return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
```

**Why it exists:**

* Decouples authentication logic from the database.
* Adds abstraction for password encoding and authority mapping.

---

# 🟢 ⑦ Step 6 – SecurityContextHolder

Once authenticated:

* The token is stored in `SecurityContextHolder`:

```java
SecurityContextHolder.getContext().setAuthentication(authenticatedToken);
```

* `SecurityContextHolder` is a **ThreadLocal storage**, meaning each request/thread has its own authentication context.
* Controllers and other beans can access the current user:

```java
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
String username = auth.getName();
```

**Advanced note:** For async or reactive applications, the context must be propagated manually.

---

# 🟣 ⑧ Step 7 – DispatcherServlet → Controller

After authentication:

* The request proceeds through the remaining filters.
* Hits the **DispatcherServlet** and then the target controller.
* You can access the authenticated user either via `SecurityContextHolder` or method injection:

```java
@GetMapping("/dashboard")
public String dashboard(@AuthenticationPrincipal UserDetails user) {
    return "Welcome " + user.getUsername();
}
```

---

# 🟡 ⑨ Step 8 – Optional In-Memory Authentication

For testing or small applications:

```java
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
        .username("rabbani")
        .password(passwordEncoder().encode("1234"))
        .roles("USER")
        .build();
    return new InMemoryUserDetailsManager(user);
}
```

* Eliminates database dependency.
* Still uses the same authentication pipeline: filter → manager → provider → context.

---

# 🟠 ⑩ Advanced Design Insights

1. **Filter-based security** ensures authentication before business logic.
2. **Strategy pattern in ProviderManager** makes Spring extensible.
3. **SecurityContextHolder** isolation ensures thread-safe per-request context.
4. **Delegation to DaoAuthenticationProvider** allows flexible user loading & password validation.
5. **ExceptionTranslationFilter** cleanly handles security exceptions and translates them into HTTP responses.
6. **ThreadLocal Storage** for authentication ensures performance but requires care in async threads.

---

# 🔴 ⑪ Complete Flow Diagram (Expert Level)

```
Client (/login)
        ↓
Tomcat / Servlet Container
        ↓
Servlet Filter Chain
        ↓
FilterChainProxy
        ↓
Security Filter Chain
   ├─ SecurityContextPersistenceFilter (load/save)
   ├─ UsernamePasswordAuthenticationFilter (extract credentials)
   ├─ ExceptionTranslationFilter
   ├─ FilterSecurityInterceptor
        ↓
AuthenticationManager (ProviderManager)
        ↓
AuthenticationProvider (DaoAuthenticationProvider)
        ↓
UserDetailsService → fetch user from DB
        ↓
PasswordEncoder → match password
        ↓
Authenticated UsernamePasswordAuthenticationToken
        ↓
SecurityContextHolder (ThreadLocal)
        ↓
DispatcherServlet → Controller
        ↓
Response
```

---

✅ **Key Takeaways for 2+ Years Experienced Developers**

* Spring Security is **filter-based and pre-controller**.
* **AuthenticationManager + Providers** form a **strategy-based extensible system**.
* **SecurityContextHolder** is **ThreadLocal**, crucial for thread safety and async.
* Understanding **filter order** and **provider selection** is essential for debugging login/authorization issues.
* You can customize almost every layer: filters, providers, context storage, password encoding.

Perfect! Let’s create a **fully labeled, expert-level Spring Security flow diagram** that shows **class-level internals, method calls, and thread context propagation**. I’ll explain it as I go so it’s clear how each component interacts internally.

---

# 🔵 Expert-Level Spring Security Flow Diagram

Here’s the textual version of the diagram (you can visualize it or draw it in a tool like Lucidchart or draw.io):

```
┌───────────────┐
│   Client      │
│ (Browser/API) │
└───────┬───────┘
        │ POST /login
        ▼
┌───────────────┐
│   Tomcat      │
│  (Embedded)   │
└───────┬───────┘
        │
        ▼
┌───────────────────────────────┐
│ Servlet Filter Chain          │
│ (Standard Servlet Filters)    │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│   FilterChainProxy             │
│  (Spring Security Delegator)   │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ Security Filter Chain          │
│ 1. SecurityContextPersistence  │
│ 2. UsernamePasswordAuthenticationFilter  │
│ 3. ExceptionTranslationFilter  │
│ 4. ConcurrentSessionFilter     │
│ 5. FilterSecurityInterceptor   │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ UsernamePasswordAuthenticationFilter │
│ - extract credentials                 │
│ - create UsernamePasswordAuthenticationToken │
│ - delegate to AuthenticationManager  │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ AuthenticationManager (ProviderManager) │
│ - holds List<AuthenticationProvider>    │
│ - loops providers:                      │
│     supports(token) → authenticate(token) │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ AuthenticationProvider          │
│ (DaoAuthenticationProvider)     │
│ - fetch UserDetailsService       │
│ - passwordEncoder.matches()      │
│ - returns authenticated token   │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ UserDetailsService / Custom    │
│ - loadUserByUsername()         │
│ - fetch user from DB / memory  │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ PasswordEncoder (BCrypt/Custom) │
│ - encode(rawPassword)           │
│ - matches(raw, encoded)         │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ SecurityContextHolder           │
│ - ThreadLocal storage           │
│ - setAuthentication(authenticatedToken) │
│ - getAuthentication()           │
└───────┬──────────────────────┘
        │
        ▼
┌───────────────────────────────┐
│ DispatcherServlet → Controller │
│ - @AuthenticationPrincipal     │
│ - SecurityContextHolder access │
└──────────────┬────────────────┘
               ▼
           Response to Client
```

---

# 🔴 Key Features in the Diagram for Experienced Developers

1. **Thread Context**

   * `SecurityContextHolder` uses **ThreadLocal**, which ensures each request has isolated authentication info.
   * In async tasks, reactive streams, or `@Async`, you need to manually propagate context.

2. **Filter Order & Responsibility**

   * SecurityContextPersistenceFilter → loads context
   * UsernamePasswordAuthenticationFilter → authentication
   * ExceptionTranslationFilter → converts exceptions to HTTP errors
   * FilterSecurityInterceptor → final authorization check

3. **ProviderManager & Strategy Pattern**

   * Holds multiple `AuthenticationProvider`s.
   * Each provider can be a separate strategy (DB, LDAP, OAuth2, JWT, Custom).

4. **PasswordEncoder**

   * Critical for secure password handling.
   * Supports BCrypt, Argon2, PBKDF2, or custom encoders.
   * DaoAuthenticationProvider calls it **after user fetch** for flexibility.

5. **Extensibility Points**

   * Filters: extend UsernamePasswordAuthenticationFilter for MFA.
   * Providers: implement custom AuthenticationProvider.
   * Context storage: can override SecurityContextRepository for stateless JWT.

6. **Exception Handling**

   * ExceptionTranslationFilter ensures Spring Security exceptions do not propagate as raw stack traces.
   * Maps exceptions to 401 (Unauthorized) or 403 (Forbidden).

---

# 🟢 Optional: Visual Representation (ASCII + Flow Arrows)

```
[Client] 
   │
   ▼
[Tomcat] 
   │
   ▼
[Servlet Filter Chain] ──> [FilterChainProxy] 
   │                              │
   ▼                              ▼
[Security Filters] ─────────> [UsernamePasswordAuthenticationFilter]
                                       │
                                       ▼
                           [AuthenticationManager / ProviderManager]
                                       │
                                       ▼
                            [DaoAuthenticationProvider / Other Providers]
                                       │
               ┌───────────────────────┴───────────────────────┐
               ▼                                               ▼
      [UserDetailsService]                              [PasswordEncoder]
               │                                               │
               └───────────── Authenticated Token ─────────────┘
                                       │
                                       ▼
                          [SecurityContextHolder (ThreadLocal)]
                                       │
                                       ▼
                           [DispatcherServlet → Controller]
                                       │
                                       ▼
                                  Response
```

---
Perfect 🔥 — now we are moving into **JWT (JSON Web Token)** and how it works internally, especially in a Spring Security context.

I’ll explain this clearly and professionally (suitable for 2+ years experience), with structured flow diagrams and proper theoretical explanation.

---

# 🔵 ① What is JWT (JSON Web Token)?

A **JWT (JSON Web Token)** is a **compact, self-contained, secure token format** used to transmit information between two parties as a JSON object.

It is commonly used for:

* Stateless authentication
* Authorization in REST APIs
* Microservices communication
* OAuth2 token representation

A JWT is:

* Digitally signed
* URL-safe
* Stateless (server does not store session)

---

# 🟢 ② Structure of JWT (3 Parts)

A JWT consists of **three parts**, separated by dots (`.`):

```
xxxxx.yyyyy.zzzzz
```

```
HEADER.PAYLOAD.SIGNATURE
```

Example:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
.
XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd20
```

---

# 🟡 ③ JWT Part 1 – Header

The header typically contains:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Meaning:

* `alg` → Algorithm used to sign token (HS256 = HMAC SHA-256)
* `typ` → Token type (JWT)

Then it is:

```
Base64URL Encoded
```

So:

```
Encoded Header = Base64UrlEncode(header JSON)
```

---

# 🟠 ④ JWT Part 2 – Payload

Payload contains **claims** (data).

Example:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1741651200
}
```

Common claims:

| Claim | Meaning           |
| ----- | ----------------- |
| sub   | Subject (user id) |
| name  | Username          |
| iat   | Issued At         |
| exp   | Expiration Time   |
| role  | User roles        |

This is also:

```
Base64Url Encoded
```

Important:

Payload is NOT encrypted.
It is only encoded. Anyone can decode it.

---

# 🔴 ⑤ JWT Part 3 – Signature

Signature ensures **integrity and authenticity**.

For HS256:

```
HMACSHA256(
    Base64UrlEncode(header) + "." +
    Base64UrlEncode(payload),
    secretKey
)
```

Then signature is Base64Url encoded.

This guarantees:

* If payload is changed → signature changes
* If secret is wrong → signature verification fails

---

# 🔵 ⑥ Visual JWT Creation Flow

```
Header JSON
     ↓
Base64UrlEncode
     ↓
Encoded Header

Payload JSON
     ↓
Base64UrlEncode
     ↓
Encoded Payload

Encoded Header + "." + Encoded Payload
     ↓
HMAC-SHA256 using Secret Key
     ↓
Base64UrlEncode
     ↓
Encoded Signature

Final JWT:
EncodedHeader.EncodedPayload.EncodedSignature
```

---

# 🟢 ⑦ JWT Authentication Flow (Client-Server)

Now let’s understand the complete login + token flow.

---

## 🔐 Step 1 – Client Sends Credentials

```
POST /login
username + password
```

---

## 🔐 Step 2 – Server Validates Credentials

Spring Security:

* Uses AuthenticationManager
* Validates via DaoAuthenticationProvider
* If valid → generate JWT

---

## 🔐 Step 3 – Server Generates JWT

Server creates token:

```
Header
Payload (sub, role, iat, exp)
Secret Key
```

Signs token → sends to client.

```
Response:
{
   "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 🔐 Step 4 – Client Uses Token

For future requests:

```
GET /dashboard
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 🔐 Step 5 – Server Validates Token

Server:

1. Extract token
2. Split by `.`
3. Recalculate signature
4. Compare signatures
5. Check expiration (exp)
6. If valid → allow access

---

# 🔴 ⑧ JWT Validation Flow (Important)

```
Incoming Request
       ↓
Extract Authorization Header
       ↓
Split token (.)
       ↓
Decode header + payload
       ↓
Recreate signature using secret
       ↓
Compare with token signature
       ↓
Check exp (expiration)
       ↓
Valid ? YES → Allow
         NO → Reject (401)
```

---

# 🟣 ⑨ Access Token + Refresh Token Flow

JWT systems often use:

* Access Token (short-lived)
* Refresh Token (long-lived)

Flow:

```
Client logs in
   ↓
Server sends:
   - Access Token (15 min)
   - Refresh Token (7 days)
   ↓
Access Token expires
   ↓
Client sends refresh token
   ↓
Server verifies refresh token
   ↓
Generates new access token
```

This avoids frequent re-login.

---

# 🔵 ⑩ Stateless Nature of JWT

Traditional session-based auth:

```
Server stores session
```

JWT-based auth:

```
Server stores nothing
Token contains everything
```

That is why JWT is called:

```
Stateless Authentication
```

Better scalability for microservices.

---

# 🟢 ⑪ Spring Security + JWT Flow

In Spring:

Instead of `UsernamePasswordAuthenticationFilter`, we use:

```
JwtAuthenticationFilter (Custom OncePerRequestFilter)
```

Flow:

```
Client Request
       ↓
JwtFilter
       ↓
Extract Bearer Token
       ↓
Validate Token
       ↓
Create Authentication Object
       ↓
SecurityContextHolder.setAuthentication()
       ↓
Controller
```

Example filter snippet:

```java
String token = request.getHeader("Authorization");

if (token != null && token.startsWith("Bearer ")) {
    token = token.substring(7);

    if (jwtService.validateToken(token)) {
        String username = jwtService.extractUsername(token);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
```

---

# 🔴 ⑫ Complete JWT System Diagram

```
CLIENT
   │
   │ 1. Send username/password
   ▼
SERVER (/login)
   │
   │ 2. Validate credentials
   │
   │ 3. Generate JWT (Header + Payload + Signature)
   ▼
CLIENT receives token
   │
   │ 4. Sends token in Authorization header
   ▼
SERVER (Every request)
   │
   │ 5. Validate signature
   │ 6. Check expiration
   │ 7. Set Authentication in SecurityContext
   ▼
Controller executes
```

---

# 🔵 ⑬ Important Security Notes (Professional Level)

* Never store sensitive data in payload.
* Always use HTTPS.
* Use short-lived access tokens.
* Use strong secret keys.
* Consider RS256 (public/private key) for microservices.
* Always validate expiration (exp).
* Blacklisting required for logout in stateless systems.

---



# 🔵 ① Complete JWT Authentication Flow in Spring Security (Beginner to Advanced Understanding)

Now this diagram represents something very important — **JWT-based authentication flow** in Spring Security.

Unlike form login (session-based authentication), JWT works in a **stateless** way. That means the server does not store session data. Instead, every request must carry authentication information inside a token.

Let’s understand everything from the beginning in a connected and clear way.

---

# 🟢 ② Two Types of Requests in JWT System

From your diagram, you can see two flows:

1. **Login Request (`/login`)**
2. **Secured Requests (All other API calls)**

These two flows behave differently.

Login request is used to generate a token.
Secured requests are used to validate that token.

---

# 🟣 ③ Step 1 – Login Request Flow (`/login`)

When a user sends:

```
POST /login
{
   "username": "rabbani",
   "password": "1234"
}
```

This request is considered a **non-secured authentication request**.

So it goes like this:

```
HTTP Request
   ↓
Security Filters
   ↓
Login Controller
```

Inside the Login Controller, you manually authenticate using:

```
AuthenticationManager
```

Example:

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()
                        )
                );

        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(request.getUsername());
        }

        throw new RuntimeException("Invalid credentials");
    }
}
```

Now internally what happens?

---

# 🟡 ④ AuthenticationManager During Login

When you call:

```java
authenticationManager.authenticate(...)
```

Spring does the following:

* ProviderManager loops through AuthenticationProviders
* DaoAuthenticationProvider is selected
* UserDetailsService loads user
* PasswordEncoder verifies password
* If correct → authenticated object returned

Once authentication is successful:

You generate a JWT token and return it to the client.

Example token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Now the client stores this token (usually in localStorage or memory).

---

# 🟠 ⑤ Step 2 – Secured API Request Flow (With JWT)

Now suppose the client calls:

```
GET /api/dashboard
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

This is a secured request.

Now the request goes through:

```
HTTP Request
   ↓
Security Filters
   ↓
Internal Spring Security Filter Chain
   ↓
JwtAuthFilter
```

This is where JWT magic happens.

---

# 🔵 ⑥ JwtAuthFilter – The Heart of JWT Authentication

This filter runs **before UsernamePasswordAuthenticationFilter**.

Its job is:

1. Extract Authorization header
2. Extract token
3. Validate token
4. Extract username from token
5. Load user from database
6. Set authentication in SecurityContextHolder

Example:

```java
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

        if (username != null &&
            SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails =
                    userDetailsService.loadUserByUsername(username);

            if (jwtService.validateToken(token, userDetails)) {

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                SecurityContextHolder.getContext()
                        .setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
```

This is exactly what your diagram shows:

Fetch token → Extract user → Validate → Add to SecurityContextHolder.

---

# 🟣 ⑦ Why SecurityContextHolder Is Important Here?

Spring Security does not check JWT automatically.

It only checks:

```
Is there an Authentication object in SecurityContextHolder?
```

If yes → request is authenticated
If no → 401 Unauthorized

That’s why your JwtAuthFilter must set authentication manually.

---

# 🟡 ⑧ UsernamePasswordAuthenticationFilter in JWT Flow

In your diagram, you see:

```
UsernamePasswordAuthenticationFilter checks authentication in the SecurityContextHolder and continues the chain
```

Exactly.

If JwtAuthFilter already set authentication, then UsernamePasswordAuthenticationFilter will see that authentication exists and simply allow the request to proceed.

Then request reaches:

```
DispatcherServlet → Controller
```

Inside controller, you can get logged-in user:

```java
@GetMapping("/dashboard")
public String dashboard(Authentication authentication) {
    return "Welcome " + authentication.getName();
}
```

---

# 🟠 ⑨ JWT Service Example (Token Generation & Validation)

Here’s a simple example:

```java
@Service
public class JwtService {

    private final String SECRET = "mysecretkey";

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername());
    }
}
```

---

# 🔴 ⑩ Why JWT Is Stateless?

In session-based authentication:

* Server stores session in memory
* Client sends JSESSIONID cookie

In JWT:

* Server does NOT store anything
* Client sends token every time
* Token contains username & expiry
* Server validates token signature

That’s why it scales better in microservices.

---

# 🔵 ⑪ Complete JWT Flow from Your Diagram (Connected Version)
```
Login Flow:

Client → `/login`
↓
Login Controller
↓
AuthenticationManager
↓
UserDetailsService + PasswordEncoder
↓
Generate JWT
↓
Return JWT to client

Secured Request Flow:

Client sends token in header
↓
Security Filter Chain
↓
JwtAuthFilter
↓
Extract token
↓
Extract username
↓
Validate token
↓
Load user
↓
Set Authentication in SecurityContextHolder
↓
Continue filter chain
↓
DispatcherServlet
↓
Controller
↓
Get user from SecurityContextHolder
```
That is the complete JWT architecture in Spring Security.

---

# 🔵 JWT-Only Security — **Improved Notes with Detailed Comments (Interview Ready)**

Rabbani, below is your **fully polished version with inline comments** so that:

* ✅ Easy to revise before interviews
* ✅ Easy to explain to beginners
* ✅ Easy to debug in real projects
* ✅ Production mindset clear

I kept your architecture but added **important explanations inside the code**.

---

# 🟢 ① WebSecurityConfig — Security Brain (With Comments)

```java
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity // 🔐 enables @PreAuthorize, @PostAuthorize etc.
public class WebSecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // ❌ Disable CSRF because we are using stateless JWT
            .csrf(csrf -> csrf.disable())

            // 🔥 VERY IMPORTANT: make Spring Security stateless
            // → no session will be created
            // → every request must carry JWT
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 🔐 Authorization rules (URL level security)
            .authorizeHttpRequests(auth -> auth

                // ✅ Public endpoints (no authentication required)
                .requestMatchers("/public/**", "/auth/**").permitAll()

                // ✅ Only ADMIN role can access /admin/**
                // Spring internally checks for authority: ROLE_ADMIN
                .requestMatchers("/admin/**").hasRole("ADMIN")

                // ✅ Either DOCTOR or ADMIN can access
                .requestMatchers("/doctors/**")
                    .hasAnyRole("DOCTOR", "ADMIN")

                // 🔒 All other endpoints must be authenticated
                .anyRequest().authenticated()
            )

            // ⚠️ Exception handling for better API responses
            .exceptionHandling(ex -> ex

                // 🔴 401 → user is NOT authenticated
                .authenticationEntryPoint((req, res, e) -> {
                    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    res.getWriter().write("Unauthorized: Invalid or missing token");
                })

                // 🔴 403 → user authenticated but NO permission
                .accessDeniedHandler((req, res, e) -> {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write("Forbidden: Access denied");
                })
            )

            // 🔥 Add JWT filter BEFORE Spring’s login filter
            // so token is validated early in filter chain
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // 🔥 Expose AuthenticationManager bean
    // required for manual authentication in AuthService
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // 🔐 Password encoder used during signup & login
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

---

# 🟣 ② JwtAuthFilter — **Heart of JWT Authentication**

👉 Runs **on every request**

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthUtil authUtil;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {

        // 🔍 Read Authorization header
        String authHeader = request.getHeader("Authorization");

        // ✅ If header missing OR not Bearer → skip filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            // ✂️ Extract token after "Bearer "
            String token = authHeader.substring(7);

            // 🔍 Extract username from JWT
            String username = authUtil.extractUsername(token);

            // ✅ Only authenticate if not already authenticated
            if (username != null &&
                SecurityContextHolder.getContext().getAuthentication() == null) {

                // 🔎 Load user from DB
                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                // 🔐 Validate token
                if (authUtil.validateToken(token, userDetails)) {

                    // 🧠 Create authentication object
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities());

                    // ✅ Store authentication in SecurityContext
                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication);
                }
            }

        } catch (Exception ex) {
            // ⚠️ Token invalid / expired / malformed
            log.error("JWT validation failed: {}", ex.getMessage());
        }

        // 👉 Continue filter chain
        filterChain.doFilter(request, response);
    }
}
```

---

# 🟡 ③ AuthUtil — JWT Utility (With Deep Comments)

```java
@Component
@Slf4j
public class AuthUtil {

    @Value("${jwt.secretKey}")
    private String jwtSecretKey;

    // 🔐 Create HMAC key from secret
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

    // ===============================
    // 🔐 GENERATE JWT TOKEN
    // ===============================
    public String generateAccessToken(User user) {

        return Jwts.builder()
                .subject(user.getUsername())      // 👤 who is the user
                .claim("userId", user.getId())    // ➕ custom claim
                .issuedAt(new Date())             // ⏰ token creation time
                .expiration(new Date(
                        System.currentTimeMillis() + 1000 * 60 * 10)) // ⏳ expiry
                .signWith(getSecretKey())         // 🔐 sign token
                .compact();
    }

    // ===============================
    // 🔍 EXTRACT USERNAME
    // ===============================
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // ===============================
    // ✅ VALIDATE TOKEN
    // ===============================
    public boolean validateToken(String token, UserDetails userDetails) {

        String username = extractUsername(token);

        return username.equals(userDetails.getUsername())
                && !isTokenExpired(token);
    }

    // ===============================
    // 🔎 INTERNAL HELPERS
    // ===============================
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
```

---

# 🔴 ④ AuthService — Login & Signup (With Comments)

```java
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PatientRepository patientRepository;

    // ===============================
    // 🔐 LOGIN FLOW
    // ===============================
    public LoginResponseDto login(LoginRequestDto request) {

        // 🔥 This triggers Spring Security authentication flow
        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()));

        // ✅ If credentials correct → principal contains User
        User user = (User) authentication.getPrincipal();

        // 🎫 Generate JWT
        String token = authUtil.generateAccessToken(user);

        return new LoginResponseDto(token, user.getId());
    }

    // ===============================
    // 🧾 SIGNUP FLOW
    // ===============================
    public SignupResponseDto signup(SignUpRequestDto dto) {

        // ❌ Prevent duplicate users
        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("User already exists");
        }

        // 🔐 Encode password before saving
        User user = User.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .roles(dto.getRoles())
                .providerType(AuthProviderType.EMAIL)
                .build();

        user = userRepository.save(user);

        // 👤 Create patient profile
        Patient patient = Patient.builder()
                .name(dto.getName())
                .email(dto.getUsername())
                .user(user)
                .build();

        patientRepository.save(patient);

        return new SignupResponseDto(user.getId(), user.getUsername());
    }
}
```

---

# 🟢 ⑤ Mental Flow (Interview Gold)

## 🔐 Login

```
Client → /auth/login
       → AuthenticationManager
       → UserDetailsService
       → PasswordEncoder
       → JWT generated
```

## 🔐 Secured Request

```
Client → Authorization: Bearer token
       → JwtAuthFilter
       → validate token
       → set SecurityContext
       → role check
       → Controller
```

---



