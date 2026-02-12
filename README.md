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



