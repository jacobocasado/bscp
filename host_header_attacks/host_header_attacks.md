# What is the HTTP Host header?
The HTTP `Host` header is a **mandatory request header as of HTTP/1.1**. It specifies **the domain name that the client wants to access.**
If a user visits `https://page.com`, their browser will compose a request with the host header `Host: page.com`.

In some cases, such as when the request has been forwarded by an intermediary system, the Host value may be altered before it reaches the intended back-end component. We will discuss this scenario in more detail below.

# What is the purpose of the HTTP Host header?
The purpose of this header is to identify which back-end components the client wants to communicate with. It is basically used for routing purposes.

Historically, this ambiguity didn't exist because each IP address would only host content for a single domain. Now, a single IP can host different domain (virtual hosting)
## Virtual hosting
One possible scenario is when a single web server hosts multiple websites or applications. This could be multiple websites with a single owner, but it is also possible for websites with different owners to be hosted on a single, shared platform. This is less common than it used to be, but still occurs with some cloud-based SaaS solutions.

In either case, although each of these distinct websites will have a different domain name, they all share a common IP address with the server. Websites hosted in this way on a single server are known as "virtual hosts".

To a normal user accessing the website, a virtual host is often indistinguishable from a website being hosted on its own dedicated server.

## Routing traffic via an intermediary (e.g., proxy)
Another common scenario is when websites are hosted on distinct back-end servers, but all traffic between the client and servers is routed through an intermediary system. This could be a simple load balancer or a reverse proxy server of some kind. This setup is especially prevalent in cases where clients access the website via a content delivery network (CDN).

In this case, even though the websites are hosted on separate back-end servers, all of their domain names resolve to a single IP address of the intermediary component. This presents some of the same challenges as virtual hosting because the reverse proxy or load balancer needs to know the appropriate back-end to which it should route each request.

## How does the HTTP Host header solve this problem?
In both of these scenarios, the Host header is relied on to specify the intended recipient. The proxy, or the server that receives the request reads this header and **knows which is the real target of the request.**

A common analogy is the process of sending a letter to somebody who lives in an apartment building. The entire building has the same street address, but behind this street address there are many different apartments that each need to receive the correct mail somehow. **One solution to this problem is simply to include the apartment number or the recipient's name in the address. In the case of HTTP messages, the Host header serves a similar purpose.**

When a browser sends the request, the target URL will resolve to the IP address of a particular server. When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly.

# What is an HTTP Host header attack?
This attack exploits vulnerable websites that handle the value of the Host header in an unsafe way. If the server **implicitely trusts the Host hedaer, or fails to escape it properly, an attacker can use this field to inject harmful payloads that manipulate server-side behavior.**

## What is an HTTP Host header attack?

HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks.

Off-the-shelf web applications typically don't know what domain they are deployed on unless it is manually specified in a configuration file during setup. When they need to know the current domain, for example, to generate an absolute URL included in an email, they may resort to retrieving the domain from the Host header:
`<a href="https://_SERVER['HOST']/support">Contact support</a>`

The header value may also be used in a variety of interactions between different systems of the website's infrastructure.

As the Host header is in fact user controllable, this practice can lead to a number of issues. If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably:
- Web cache poisoning
- Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
- Routing-based SSRF
- Classic server-side vulnerabilities, such as SQL injection
# How do HTTP Host header vulnerabilities arise?
HTTP Host header vulnerabilities typically arise due to the **flawed assumption that the header is not user controllable**. This creates implicit trust in the Host header and results in inadequate validation or escaping of its value, even though an attacker can easily modify this using tools like Burp Proxy.

Even if the Host header itself is handled more securely, depending on the configuration of the servers that deal with incoming requests, the Host can potentially be overridden by injecting other headers. Sometimes website owners are unaware that these headers are supported by default and, as a result, they may not be treated with the same level of scrutiny.

In fact, many of these vulnerabilities arise not because of insecure coding but because of insecure configuration of one or more components in the related infrastructure. These configuration issues can occur because websites integrate third-party technologies into their architecture without necessarily understanding the configuration options and their security implications.

# How to identify and exploit HTTP Host header vulnerabilities

In this section, we'll look more closely at how you can identify whether a website is vulnerable to [HTTP Host header attacks](https://portswigger.net/web-security/host-header). We'll then provide examples of how you can exploit this, along with several interactive labs that you can use to practice these exploits on a deliberately vulnerable website.

# How to test for vulnerabilities using the HTTP Host header
To test whether a website is vulnerable to attack via the HTTP Host header, you will need an intercepting proxy, such as Burp Proxy, and manual testing tools like Burp Repeater and Burp Intruder.

In short, you need to identify whether you are able to modify the Host header and still reach the target application with your request. If so, you can use this header to probe the application and observe what effect this has on the response.
## Supply an arbitrary Host header

When probing for Host header injection vulnerabilities, the first step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header.

Some intercepting proxies derive the target IP address from the Host header directly, which makes this kind of testing all but impossible; any changes you made to the header would just cause the request to be sent to a completely different IP address. However, Burp Suite accurately maintains the separation between the Host header and the target IP address. This separation allows you to supply any arbitrary or malformed Host header that you want, while still making sure that the request is sent to the intended target.

### Tip
The target URL is displayed either at the top of the panel (for Burp Repeater and Proxy interception) or on the "Target" tab in Burp Intruder. You can edit the target manually by clicking the pencil icon.

Sometimes, you will still be able to access the target website even when you supply an unexpected Host header. This could be for a number of reasons. For example, servers are sometimes configured with a default or fallback option in case they receive requests for domain names that they don't recognize. If your target website happens to be the default, you're in luck. In this case, you can begin studying what the application does with the Host header and whether this behavior is exploitable.

On the other hand, as the Host header is such a fundamental part of how the websites work, tampering with it often means you will be unable to reach the target application at all. The front-end server or load balancer that received your request may simply not know where to forward it, resulting in an "`Invalid Host header`" error of some kind. This is especially likely if your target is accessed via a CDN. In this case, you should move on to trying some of the techniques outlined below.

## Check for flawed validation
Instead of receiving an "`Invalid Host header`" response, you might find that your request is blocked as a result of some kind of security measure. For example, some websites will validate whether the Host header matches the SNI from the TLS handshake. This doesn't necessarily mean that they're immune to Host header attacks.

You should try to understand how the website parses the Host header. This can sometimes reveal loopholes that can be used to bypass the validation. For example, some parsing algorithms will omit the port from the Host header, meaning that only the domain name is validated. If you are also able to supply a non-numeric port, you can leave the domain name untouched to ensure that you reach the target application, while potentially injecting a payload via the port.
`GET /example HTTP/1.1 Host: vulnerable-website.com:bad-stuff-here`

Other sites will try to apply matching logic to allow for arbitrary subdomains. In this case, you may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one:
`GET /example HTTP/1.1 Host: notvulnerable-website.com`

Alternatively, you could take advantage of a less-secure subdomain that you have already compromised:
`GET /example HTTP/1.1 Host: hacked-subdomain.vulnerable-website.com`

For further examples of common domain-validation flaws, check out our content on [circumventing common SSRF defences](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses) and [Origin header parsing errors](https://portswigger.net/web-security/cors#errors-parsing-origin-headers).

## Send ambiguous requests
The code that validates the host and the code that does something vulnerable with it often reside in different application components or even on separate servers. By identifying and exploiting discrepancies in how they retrieve the Host header, you may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it.

The following are just a few examples of how you may be able to create ambiguous requests.

### Inject duplicate Host headers

One possible approach is to try adding duplicate Host headers. Admittedly, this will often just result in your request being blocked. However, as a browser is unlikely to ever send such a request, you may occasionally find that developers have not anticipated this scenario. In this case, you might expose some interesting behavioral quirks.

Different systems and technologies will handle this case differently, but it is common for one of the two headers to be given precedence over the other one, effectively overriding its value. When systems disagree about which header is the correct one, this can lead to discrepancies that you may be able to exploit. Consider the following request:
`GET /example HTTP/1.1 Host: vulnerable-website.com Host: bad-stuff-here`

Let's say the front-end gives precedence to the first instance of the header, but the back-end prefers the final instance. Given this scenario, you could use the first header to ensure that your request is routed to the intended target and use the second header to pass your payload into the server-side code.

### Supply an absolute URL
Although the request line typically specifies a relative path on the requested domain, many servers are also configured to understand requests for absolute URLs.

The ambiguity caused by supplying both an absolute URL and a Host header can also lead to discrepancies between different systems. Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case. You can potentially exploit these discrepancies in much the same way as duplicate Host headers.

`GET https://vulnerable-website.com/ HTTP/1.1 Host: bad-stuff-here`

Note that you may also need to experiment with different protocols. Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL.

### Add line wrapping
You can also uncover quirky behavior by indenting HTTP headers with a space character. Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value. Other servers will ignore the indented header altogether.

Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request. For example, consider the following request:
`GET /example HTTP/1.1 Host: bad-stuff-here Host: vulnerable-website.com`

The website may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them like this. If the front-end ignores the indented header, the request will be processed as an ordinary request for `vulnerable-website.com`. Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header.
## Inject host override headers
Even if you can't override the Host header using an ambiguous request, there are other possibilities for overriding its value while leaving it intact. This includes injecting your payload via one of several other HTTP headers that are designed to serve just this purpose, albeit for more innocent use cases.

As we've already discussed, websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy. In this kind of architecture, the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. This is usually not relevant for the requested functionality.

To solve this problem, the front-end may inject the `X-Forwarded-Host` header, containing the original value of the Host header from the client's initial request. For this reason, when an `X-Forwarded-Host` header is present, many frameworks will refer to this instead. You may observe this behavior even when there is no front-end that uses this header.

You can sometimes use `X-Forwarded-Host` to inject your malicious input while circumventing any validation on the Host header itself.

`GET /example HTTP/1.1 Host: vulnerable-website.com X-Forwarded-Host: bad-stuff-here`

Although `X-Forwarded-Host` is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including:

- `X-Host`
- `X-Forwarded-Server`
- `X-HTTP-Host-Override`
- `Forwarded`

### Tip
In Burp Suite, you can use the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist.

From a security perspective, it is important to note that some websites, potentially even your own, support this kind of behavior unintentionally. This is usually because one or more of these headers is enabled by default in some third-party technology that they use.

# Attack 1. Password reset poisoning
Password reset poisoning is a technique whereby an attacker manipulates a vulnerable website into generating a password reset link pointing to a domain under their control. This behavior can be leveraged to steal the secret tokens required to reset arbitrary users' passwords and, ultimately, compromise their accounts.
## How does a password reset work?
Virtually all websites that require a login also implement functionality that allows users to reset their password if they forget it. There are several ways of doing this, with varying degrees of security and practicality. One of the most common approaches goes something like this:

1. The user enters their username or email address and submits a password reset request.
2. The website checks that this user exists and then generates a temporary, unique, high-entropy token, which it associates with the user's account on the back-end.
3. The website sends an email to the user that contains a link for resetting their password. The user's unique reset token is included as a query parameter in the corresponding URL:
    
    `https://normal-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j`
4. When the user visits this URL, the website checks whether the provided token is valid and uses it to determine which account is being reset. If everything is as expected, the user is given the option to enter a new password. Finally, the token is destroyed.

This process is simple enough and relatively secure in comparison to some other approaches. However, its security relies on the principle that only the intended user has access to their email inbox and, therefore, to their unique token. Password reset poisoning is a method of stealing this token in order to change another user's password.

## How to construct a password reset poisoning attack
If the URL that is sent to the user is dynamically generated based on controllable input, such as the Host header, it may be possible to construct a password reset poisoning attack as follows:

1. The attacker obtains the victim's email address or username, as required, and submits a password reset request on their behalf. When submitting the form, they intercept the resulting HTTP request and modify the Host header so that it points to a domain that they control. For this example, we'll use `evil-user.net`.
2. The victim receives a genuine password reset email directly from the website. This seems to contain an ordinary link to reset their password and, crucially, contains a valid password reset token that is associated with their account. However, the domain name in the URL points to the attacker's server:
    
    `https://evil-user.net/reset?token=0a1b2c3d4e5f6g7h8i9j`
3. If the victim clicks this link (or it is fetched in some other way, for example, by an antivirus scanner) the password reset token will be delivered to the attacker's server.
4. The attacker can now visit the real URL for the vulnerable website and supply the victim's stolen token via the corresponding parameter. They will then be able to reset the user's password to whatever they like and subsequently log in to their account.

In a real attack, the attacker may seek to increase the probability of the victim clicking the link by first warming them up with a fake breach notification, for example.

Even if you can't control the password reset link, you can sometimes use the Host header to inject HTML into sensitive emails. Note that email clients typically don't execute JavaScript, but other HTML injection techniques like [dangling markup attacks](https://portswigger.net/web-security/cross-site-scripting/dangling-markup) may still apply.

Password reset poisoning labs: [apprentice](labs/password_reset_poisoning/apprentice.md) and [practitioner](labs/password_reset_poisoning/practitioner.md).

# Attack 2. Manipulating the header to access restricted functionality
For fairly obvious reasons, it is common for websites to restrict access to certain functionality to internal users only. However, some websites' [access control](https://portswigger.net/web-security/access-control) features are based in the Host header, which can be easily modified by the user, for example, using a Proxy like Burp Suite.

Here is a lab that covers the bypass using these headers: [host_header_authentication_bypass](labs/host_header_authentication_bypass.md)


# Attack 3. Cache poisoning via the Host header
As we have seen in [cache_poisoning](../cache_poisoning/cache_poisoning.md), we can use different fields that are not cache keys but get reflected in the cache to provoke attacks like XSS. The Host header can be one of them, and sometimes the content of this header gets reflected in the website and stored in the cache, without it being a cache key.
Here is the lab that covers this attack by using a double `Host` header to perform the attack: [host_header_cache_poisoning](labs/host_header_cache_poisoning.md)

# Attack 4. Routing-based SSRF
 Classic SSRF vulnerabilities are usually based on XXE or any exploitable business logic that sends HTTP requests to a URL derived from user-controllable input.

Routing-based SSRF relies on **exploiting the intermediary components that are in most common cloud-based architectures, as load balancers and reverse proxies.** If these components that receive requests and forward them to the appropiate back end, do not validate properly the Host header, they could be manipulated into misrouting requests to an arbitrary system of the attacker's choice. 

Load balancers and reverse proxies are fantastic targets. They sit in a privileged network position that allows them to receive requests directly from the public web, while also having access to much, if not all, of the internal network. This makes the Host header a powerful vector for SSRF attacks, potentially transforming a simple load balancer into a gateway to the entire internal network.

Two labs regarding routing the requests via the Host header and doing SSRF: [ssrf_flawed_request_parsing](labs/ssrf_flawed_request_parsing.md) and [routing_based_ssrf](labs/routing_based_ssrf.md).

# Attack 5. Connection state attacks
For performance reasons, many websites reuse connections for multiple request/response cycles with the same client. Poorly implemented HTTP servers sometimes work on the dangerous assumption that certain properties, such as the Host header, are identical for all HTTP/1.1 requests sent over the same connection. This may be true of requests sent by a browser, but isn't necessarily the case for a sequence of requests sent from Burp Repeater. This can lead to a number of potential issues.

For example, you may occasionally encounter servers that only perform thorough validation on the first request they receive over a new connection. In this case, you can potentially bypass this validation by sending an innocent-looking initial request then following up with your malicious one down the same connection.