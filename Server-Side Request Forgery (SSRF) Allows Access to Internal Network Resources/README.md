# Server-Side Request Forgery (SSRF) in Landing Page Import Feature Allows Access to Internal Network Resources in GoPhish v0.12.1

## Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in GoPhish v0.12.1 within the **"Import Site"** functionality used while creating Landing Pages. The vulnerable implementation allows an authenticated administrator to force the GoPhish server to send arbitrary HTTP requests to internal network resources. Due to flawed default deny-list logic, requests to loopback and private network addresses are permitted by default, enabling attackers to access internal services, scan internal networks, and potentially pivot into otherwise inaccessible systems.

## Product Information

**Vendor:** GoPhish  
**Product:** GoPhish  
**Affected Versions:** v0.12.1  
**CVSS v3.1:** CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L - 8.0 (High)    

## Technical Details

The vulnerability originates from insecure default access control logic implemented in the `restrictedControl` function within `dialer/dialer.go`.

By default, GoPhish initializes a minimal deny list containing only the link-local address range:

```go
// File: dialer/dialer.go, line 101
var defaultDeny = []string{
    "169.254.0.0/16", // Link-local (used for VPS instance metadata)
}
```

The `restrictedControl` function subsequently initializes the active deny list using this minimal configuration:

```go
// File: dialer/dialer.go, line 158
denyList := defaultDeny
```

A more comprehensive deny list (`allInternal`) is only enabled when administrators explicitly configure an allowlist:

```go
// File: dialer/dialer.go, line 159
if len(allowed) > 0 {
    denyList = allInternal
}
```

Because the `allowed` list is empty by default, the condition above is not satisfied in standard installations. As a result, GoPhish only blocks requests to `169.254.0.0/16` while still allowing requests to:

* `127.0.0.0/8` (loopback addresses)
* `10.0.0.0/8` (RFC1918 private network)
* `172.16.0.0/12` (RFC1918 private network)
* `192.168.0.0/16` (RFC1918 private network)
* Other sensitive internal IP ranges

This insecure default behavior allows authenticated users to leverage the GoPhish server as an internal network proxy.

## Vulnerable Component

**Endpoint:** `POST /api/import/site`  
**File:** `/gophish-0.12.1/controllers/api/import.go`  
**Function:** `ImportSite()` / `restrictedControl()`  
**Parameter:** `url`  

**Additional Affected File:**

* `/gophish-0.12.1/dialer/dialer.go`

## Reproduction Steps

1. Log in to the GoPhish administrative panel.  
2. Navigate to **Landing Pages**.  
3. Click **New Page**.  

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Server-Side%20Request%20Forgery%20\(SSRF\)%20Allows%20Access%20to%20Internal%20Network%20Resources/%5B1%5D%20Landing%20Page%20Feature.png)

4. Inside the page creation dialog, click **Import Site**.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Server-Side%20Request%20Forgery%20\(SSRF\)%20Allows%20Access%20to%20Internal%20Network%20Resources/%5B2%5D%20Import%20Site%20Feature%20at%20%5B%2B%5D%20New%20Page.png)

5. In the URL field, provide an internal network address such as:

```text
http://127.0.0.1:3333
```

or

```text
http://192.168.1.1/
```

6. Click **Import**.
7. Observe that GoPhish successfully fetches content from the internal resource and displays it within the application.

## Proof of Concept

An authenticated administrator can abuse the vulnerable functionality to access internal-only resources directly from the GoPhish server.

Example payload:

```text
http://127.0.0.1:3333
```

The following screenshot demonstrates importing content from an internal network host using the vulnerable feature:

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Server-Side%20Request%20Forgery%20\(SSRF\)%20Allows%20Access%20to%20Internal%20Network%20Resources/%5B3%5D%20Accessing%20Internal%20Network%20via%20Import%20Site%20Feature.png)

The request succeeds and the response from the internal service is returned to the user, confirming successful SSRF.

Additional testing confirmed that multiple internal systems can be reached through the GoPhish server, effectively allowing network pivoting:

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Server-Side%20Request%20Forgery%20\(SSRF\)%20Allows%20Access%20to%20Internal%20Network%20Resources/%5B4%5D%20Internal%20Network%20Successfully%20Pivoted.png)

## Impact

An authenticated attacker can abuse the vulnerable functionality to enumerate and map internal network infrastructure, access internal web applications, interact with unauthenticated administrative interfaces, and potentially exploit additional vulnerabilities in internal services that are not directly exposed to the internet. Since the vulnerability enables bypassing network segmentation boundaries, it significantly increases the overall attack surface and may facilitate lateral movement within the organization's infrastructure.

## Remediation

The application should adopt a secure-by-default approach by blocking all internal and loopback network ranges unless explicitly allowed by administrators. The `restrictedControl` function should initialize `denyList` using `allInternal` instead of `defaultDeny`. Additionally, requests targeting loopback, private, multicast, and link-local addresses should always be denied unless administrators intentionally configure a strict allowlist. Implementing comprehensive SSRF protections, DNS rebinding defenses, and robust URL validation is strongly recommended.

```text
This vulnerability was discovered by Ashik Mohamed (ashikmd7) on 21/06/2026
```
