# What is web cache poisoning?
Web cache poisoning is a technique where an attacker exploits the behavior of a web server and **its cache so a harmful HTTP response is served to other users.** The attacker manipulates the cache of the server by analyzing how it manages the cache, and prepares an attack.

Fundamentally, web cache poisoning involves two phases. First, the attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims.

A poisoned web cache can be used to distribute numerous attacks exploiting different vulnerabilities, like XSS, JavaScript injection, open redirection, etc.

### How does a web cache work?
To understand how web cache poisoning vulnerabilities arise, it is important to have a basic understanding of how web caches work.

If a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience, especially during busy periods. Caching is primarily a means of reducing such issues.

The cache sits between the server and the user, where it saves (caches) the responses to particular requests, usually for a fixed amount of time. If another user then sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end. This greatly eases the load on the server by reducing the number of duplicate requests it has to handle.

![](imgs/caching.svg)

When the cache receives an HTTP request, it has to determine if it has the cached response to that request or if it has to forward the request for handling by the back-end server.
Caches identify equivalent requests by comparing a predefined subsets of the request's components. These part of the request that is compared to determine whether return the cached response or forward it is called "Cache key".

The "Cache key" usually contains the request line and the `Host` header. The rest of the components of the request that are not taken into consideration are said to be "Unkeyed".

If the cache key of a request matches the key of a previous request, then the **cache considers them to be equivalent and it will serve a copy of the cached response that was returned to the previous request.** This applies to every following request with the matching cache key, until the cached response expires.

# What is the impact of a web cache poisoning attack?
The impact of web cache poisoning is heavily dependent on two key factors:

- **What exactly the attacker can successfully get cached**  
    As the poisoned cache is more a means of distribution than a standalone attack, the impact of web cache poisoning is inextricably linked **to how harmful the injected payload is**. As with most kinds of attack, web cache poisoning can also be used in combination with other attacks to escalate the potential impact even further.
- **The amount of traffic on the affected page**  
    The poisoned response will only be served to **users who visit the affected page while the cache is poisoned.** As a result, the impact can range from non-existent to massive depending on whether the page is popular or not. If an attacker managed to poison a cached response on the home page of a major website, for example, the attack could affect thousands of users without any subsequent interaction from the attacker.

Note that the duration of a cache entry doesn't necessarily affect the impact of web cache poisoning. **An attack can usually be scripted in such a way that it re-poisons the cache indefinitely.** Therefore, the time of the cache does not matter for our considerations.

# Constructing a web cache poisoning attack
Generally speaking, constructing a web cache poisoning attack involves 3 steps:
1. Identify unkeyed inputs (inputs that are not relevant to decide if cache or not)
2. Create a harmful response from the back-end server
3. Get the response cached

We will go through each of the phases.

## Phase 1: Identify unkeyed inputs
Any web cache poisoning attack relies on the manipulation of unkeyed inputs, such as **headers.**
Web caches ignore unkeyed inputs when deciding whether to serve a cached response to an user.
This means that we can use these headers to inject our payload, and elicit a "poisoned" response which, if cached, will be served to all users **whose requests** have the matching cache key. Then, the unkeyed inputs will **contain the malicious payload.**

We can identify unkeyed inputs in a manual way, adding random inputs to requests and observing whether or not have an effect on the response. Usually, Burp Comparer is the tool when working manually.

Nevertheless, there is a tool that can help us a lot in this task, and it is called **param Miner**. Param Miner is a tool that guess the headers that have an effect in the response, and logs it in the Burp Professional "Issues" panel.
For example, in the following screenshot, Param Miner found an unkeyed header `X-Forwarded-Host` on the home page of the website:
![](imgs/param-miner.png)

## Step 2: Elicit a harmful response from the back-end server
The second step once we have detected where are we going to store our payload (unkeyed input), is to evaluate **how the server processes it, in order to create a harmful response.**
If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning.

## Step 3: Get the response cached

Manipulating inputs to elicit a harmful response is half the battle, but it doesn't achieve much unless you can cause the response to be cached, which can sometimes be tricky.

Whether or not a response gets cached can depend on all kinds of factors, such as the file extension, content type, route, status code, and response headers. You will probably need to devote some time to simply playing around with requests on different pages and studying how the cache behaves. Once you work out how to get a response cached that contains your malicious input, you are ready to deliver the exploit to potential victims.

# Exploiting web cache poisoning vulnerabilities
Overall, web cache poisoning vulnerabilities arise due to flaws in the **design of caches.** But sometimes this flaws are not in the design of the caches but on the implementation of these cache systems.

## Exploiting cache design flaws
We will see how cache design flaws can be exploited and attack can be leveraged.

### XSS via cache poisoning
Perhaps the simplest web cache poisoning vulnerability to exploit is when unkeyed input is reflected in a cacheable response without proper sanitization.

For example, consider the following request and response:

`GET /en?region=uk HTTP/1.1 Host: innocent-website.com X-Forwarded-Host: innocent-website.co.uk HTTP/1.1 200 OK Cache-Control: public <meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />`

Here, the value of the `X-Forwarded-Host` header is being used to dynamically generate an Open Graph image URL, which is then reflected in the response. Crucially for web cache poisoning, the `X-Forwarded-Host` header is often unkeyed. In this example, the cache can potentially be poisoned with a response containing a simple [XSS](https://portswigger.net/web-security/cross-site-scripting) payload:

`GET /en?region=uk HTTP/1.1 Host: innocent-website.com X-Forwarded-Host: a."><script>alert(1)</script>" HTTP/1.1 200 OK Cache-Control: public <meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />`

If this response was cached, all users who accessed `/en?region=uk` would be served this XSS payload. This example simply causes an alert to appear in the victim's browser, but a real attack could potentially steal passwords and hijack user accounts.

### Using web cache poisoning to exploit unsafe handling of resource imports
Some websites use **unkeyed headers to dynamically generate URLs for importing resources**, such as **externally hosted JavaScript files**. In this case, if an attacker changes the value of the appropriate header to a domain that they control, they could potentially manipulate the URL to point to **their own malicious JavaScript file instead.**

If the response containing this malicious URL is cached, the attacker's JavaScript file would be imported and executed in the browser session of any user whose request has a matching cache key.
For example, in this case, with the `X-Forwarded-Host` header
```http 
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
User-Agent: Mozilla/5.0 Firefox/57.0

HTTP/1.1 200 OK
<script src="https://evil-user.net/static/analytics.js"></script>
```

Here is a lab that covers this cache poisoning attack with a header: [cache_xxs_header](labs/cache_xxs_header.md)
### Using web cache poisoning to exploit cookie-handling vulnerabilities
Cookies are often **used to dynamically generate content in a response.** A common example might be a cookie that **indicates the user's preferred language**, which is then used to load the corresponding version of the page:

```HTTP
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
User-Agent: Mozilla/5.0 Firefox/57.0
Cookie: language=pl;
Connection: close
```

In this example, the Polish version of a blog post is being requested. Notice that the information about which language version to serve is only contained in the `Cookie` header. Let's suppose that the cache key contains the request line and the `Host` header, but not the `Cookie` header. In this case, if the response to this request is cached, then all subsequent users who tried to access this blog post would receive the Polish version as well, regardless of which language they actually selected.

This flawed handling of cookies by the cache can also be exploited using web cache poisoning techniques. In practice, however, **this vector is relatively rare in comparison to header-based cache poisoning**. When cookie-based cache poisoning vulnerabilities exist, they tend to be identified and resolved quickly because legitimate users have accidentally poisoned the cache.

Here is a lab that covers cache poisoning with a cookie: [cache_xss_cookie](labs/cache_xss_cookie.md)

### Using multiple headers to exploit web cache poisoning vulnerabilities
Some websites are vulnerable to simple web cache poisoning exploits, as demonstrated above. However, others require more sophisticated attacks and only become vulnerable when an attacker is able to craft a request that manipulates multiple unkeyed inputs.

For example, let's say a website requires secure communication using HTTPS. To enforce this, if a request that uses another protocol is received, the website dynamically generates a redirect to itself that does use HTTPS:
```
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

HTTP/1.1 301 moved permanently
Location: https://innocent-site.com/random
```

By itself, this behavior isn't necessarily vulnerable. However, by combining this with what we learned earlier about vulnerabilities in dynamically generated URLs, an attacker could potentially exploit this behavior to generate a cacheable response that redirects users to a malicious URL.

Here is a lab that covers the topic of double header cache attack: [cache_xss_double_header](labs/cache_xss_double_header.md)


### Exploiting responses that expose too much information
Sometimes websites give too much information about themselves and their behavior, and that makes them weak.

One such example is **when responses contain information about how often the cache is purged** or **how old the currently cached response is. One example is the following:**
```
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```
This does not indicate that the web is vulnerable to web cache poisoning, BUT it helps indicating **that there is a cache, and when to know the payload so it gets cached.**
This knowledge also enables far more subtle attacks. Rather than bombarding the back-end server with requests until one sticks, which could raise suspicions, the attacker can carefully time a single malicious request to poison the cache.
### Vary header
The rudimentary way that the `Vary` header is often used can also provide attackers with a helping hand. The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed.
It is commonly used to specify that the `User-Agent` header is keyed, for example, so that if the mobile version of a website is cached, this won't be served to non-mobile users by mistake.

This information can also be used to construct a **multi-step attack to target a specific subset of users.**
**For example, if the attacker knows that the `User-Agent` header is part of the cache key, by first identifying the user agent of the intended victims, they could tailor the attack so that only users with that user agent are affected.**
Alternatively, they could work out which user agent was most commonly used to access the site, and tailor the attack to affect the maximum number of users that way.

Here is a lab that covers the discovery of a cache key with the `vary` header: [cache_xss_unknown_header](labs/cache_xss_unknown_header.md)


## Exploiting cache implementation flaws
The flaws that we have seen are design flaws, like exploiting unkeyed inputs, such as HTTP headers and cookies. 
In this step, we will see specific implementations of caching systems and how they can leave websites vulnerable. As they are from implementation, the problem is often from the usage of the cache techniques and not from the libraries/frameworks.

### Cache key flaws
Generally speaking, websites take most of their input from the **URL path and the query string**. As a result, this is a well-trodden attack surface for various hacking techniques.
However, as the request line is usually part of the cache key, **these inputs have traditionally not been considered suitable for cache poisoning.** 
Any payload injected via keyed inputs would act as a cache buster, meaning your poisoned cache entry would almost certainly never be served to any other users.

On closer inspection, however, the behavior of individual caching systems is not always as you would expect. In practice, **many websites and CDNs perform various transformations on keyed components when they are saved in the cache key.** This can include:
- **Excluding the query string**
- **Filtering out specific query parameters**
- **Normalizing input in keyed components**

These transformations may introduce a few unexpected outputs. 
These are primarily based around discrepancies between the data that is written to the cache key and the data that is passed into the application code, even though it all stems from the same input. These cache key flaws can be exploited to poison the cache via inputs that may initially appear unusable.

In the case of fully integrated, application-level caches, these quirks can be even more extreme. In fact, internal caches can be so unpredictable that it is sometimes difficult to test them at all without poisoning the cache for live users.

### Cache probing methodology
The methodology of probing for implementation flaws in cache differs slightly from the classic web cache poisoning methodology. These newer techniques rely on flaws in the specific implementation and configuration of the cache, which may **vary drastically from site to site as they are implementation flaws.** This means that we need to have a deeper understanding of the target cache and its behavior.

The methodology overall consists in the following three steps:
1. Identify a suitable cache oracle
2. Probe key handling
3. Identify an exploitable gadget

### Step 1: Identify a suitable cache oracle
The first step is to identify what is often called a "cache oracle". A cache oracle is a page that **provides feedback** about the website's cache behavior. This page obviously needs to be cacheable and must indicate in some way that we received a cached response or a response directly from the server.

This feedback could have different forms, like a HTTP header with a `Cache: hit` or `Cache: miss` directive, changes on the distributed content depending of the cache status, or distinct response times (sometimes time is very important).

Ideally, the cache oracle will also reflect **the entire UTL and at least one query parameter in the response.** This will help into developing exploits later.

If we can also identify specific third-party cache libraries, we can also consult the specific implementation, for example, information about how the **default configuration of the cache library is used.** Sometimes in the documentation you can visualize **how to directly view the cache status.** For example, Akamai-based websites may support the header `Pragma: akamai-x-get-cache-key`, which you can use to display the cache key in the response headers:
`GET /?param=1 HTTP/1.1 Host: innocent-website.com Pragma: akamai-x-get-cache-key HTTP/1.1 200 OK X-Cache-Key: innocent-website.com/?param=1`

Remember to always look into the documentation, even if it is boring. 

### Step 2: Probe key handling
The next step is to investigate if the cache processes the input when generating the cache key. This is a little black box.

You should specifically look at any transformation that is taking place. Is anything being excluded from a keyed component when it is added to the cache key? Common examples are excluding specific query parameters, or even the entire query string, and removing the port from the `Host` header.
If you're fortunate enough to have direct access to the cache key, you can simply compare the key after injecting different inputs. Otherwise, you can use your understanding of the cache oracle to infer whether you received the correct cached response. For each case that you want to test, you send two similar requests and compare the responses.

Let's say that our hypothetical cache oracle is the target website's home page. This automatically redirects users to a region-specific page. It uses the `Host` header to dynamically generate the `Location` header in the response:

```http
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com/en
Cache-Status: miss
```

To test whether **the port is excluded from the cache key**, we first need to request an arbitrary port and make sure that we receive a fresh response from the server that reflects this input:
```http
GET / HTTP/1.1
Host: vulnerable-website.com:1337

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: miss
```

Next, we'll send another request, but this time we won't specify a port:
```http
GET / HTTP/1.1
Host: vulnerable-website.com

HTTP/1.1 302 Moved Permanently
Location: https://vulnerable-website.com:1337/en
Cache-Status: hit
```
As you can see, we have been served our cached response even though the `Host` header in the request does not specify a port. This proves that the port is being excluded from the cache key. Importantly, the full header is still passed into the application code and reflected in the response.

In short, although the `Host` header is keyed, the way **it is transformed (the implementation) allows us to pass a payload into the application while still preserving a normal cache key that will be mapped to other users' requests. **

You can use a similar approach to investigate any other processing of your input by the cache. Is your input being normalized in any way? How is your input stored? Do you notice any anomalies? We'll cover how to answer these questions later using concrete examples.

### Identify an exploitable gadget
By now, you should have a relatively solid understanding of how the target website's cache behaves and might have found some interesting flaws in the way the cache key is constructed. The final step is to identify a suitable gadget that you can chain with this cache key flaw. This is an important skill because the severity of any web cache poisoning attack is heavily dependent on the gadget you are able to exploit.

These gadgets will often be classic client-side vulnerabilities, such as [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) and open redirects. By combining these with web cache poisoning, you can massively escalate the severity of these attacks, turning a reflected vulnerability into a stored one. Instead of having to induce a victim to visit a specially crafted URL, your payload will automatically be served to anybody who visits the ordinary, perfectly legitimate URL.

Perhaps even more interestingly, these techniques enable you to exploit a number of unclassified vulnerabilities that are often dismissed as "unexploitable" and left unpatched. This includes the use of dynamic content in resource files, and exploits requiring malformed requests that a browser would never send.

We will see the typical cache implementation flaws:

#### Unkeyed port
The `Host` header is often part of the cache key and, as such, initially seems an unlikely candidate for injecting any kind of payload. However, some caching systems will parse the header and exclude the port from the cache key.

In this case, you can potentially use this header for web cache poisoning. For example, consider the case we saw earlier where a redirect URL was dynamically generated based on the `Host` header. This might enable you to construct a denial-of-service attack by simply adding an arbitrary port to the request. All users who browsed to the home page would be redirected to a dud port, effectively taking down the home page until the cache expired.

This kind of attack can be escalated further if the website allows you to specify a non-numeric port. You could use this to inject an XSS payload, for example.

#### Detecting an unkeyed query string
If the response explicitly tells you whether you got a cache hit or not, this transformation is relatively simple to spot - but what if it doesn't? This has the side-effect of making dynamic pages appear as though they are fully static because it can be hard to know whether you are communicating with the cache or the server.

To identify a dynamic page, you would normally observe how changing a parameter value has an effect on the response. But if the query string is unkeyed, most of the time you would still get a cache hit, and therefore an unchanged response, regardless of any parameters you add. Clearly, this also makes classic cache-buster query parameters redundant.

Fortunately, there are alternative ways of adding a cache buster, such as adding it to a keyed header that doesn't interfere with the application's behavior. Some typical examples include:

```http
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

If you use Param Miner, you can also select the options "Add static/dynamic cache buster" and "Include cache busters in headers". It will then automatically add a cache buster to commonly keyed headers in any requests that you send using Burp's manual testing tools.

Another approach is to see whether there are any discrepancies between how the cache and the back-end normalize the path of the request. As the path is almost guaranteed to be keyed, you can sometimes exploit this to issue requests with different keys that still hit the same endpoint. For example, the following entries might all be cached separately but treated as equivalent to `GET /` on the back-end:
Apache: `GET //   `
Nginx: `GET /%2F   `
PHP: `GET /index.php/xyz   `
.NET `GET /(A(xyz)/   `

This transformation can sometimes mask what would otherwise be glaringly obvious [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerabilities. If penetration testers or automated scanners only receive cached responses without realizing, it can appear as though there is no reflected XSS on the page.
#### Exploiting an unkeyed query string
Excluding the query string from the cache key can actually make these reflected XSS vulnerabilities even more severe.

Usually, such an attack would rely on inducing the victim to visit a maliciously crafted URL. However, poisoning the cache via an unkeyed query string would cause the payload to be served to users who visit what would otherwise be a perfectly normal URL. This has the potential to impact a far greater number of victims with no further interaction from the attacker.

Here is a lab that consists in poisoning the cache with an unkeyed query string, using this script to poison the cache and using the `Origin` header as the cache buster: [cache_query_string](labs/cache_query_string.md)


#### Parameter cloaking
Let's assume that the algorithm for excluding parameters from the cache key behaves in this way, but the server's algorithm only accepts the first `?` as a delimiter. Consider the following request:
`GET /?example=123?excluded_param=bad-stuff-here`

In this case, the cache would identify two parameters and exclude the second one from the cache key. However, the server doesn't accept the second `?` as a delimiter and instead only sees one parameter, `example`, whose value is the entire rest of the query string, including our payload. If the value of `example` is passed into a useful gadget, we have successfully injected our payload without affecting the cache key.

#### Exploiting parameter parsing quirks
Similar parameter cloaking issues can arise in the opposite scenario, where the back-end identifies distinct parameters that the cache does not. The Ruby on Rails framework, for example, interprets both ampersands (&) and semicolons (;) as delimiters. When used in conjunction with a cache that does not allow this, you can potentially exploit another quirk to override the value of a keyed parameter in the application logic.

Consider the following request:

`GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here`

As the names suggest, `keyed_param` is included in the cache key, but `excluded_param` is not. Many caches will only interpret this as two parameters, delimited by the ampersand:

1. `keyed_param=abc`
2. `excluded_param=123;keyed_param=bad-stuff-here`

Once the parsing algorithm removes the `excluded_param`, the cache key will only contain `keyed_param=abc`. On the back-end, however, Ruby on Rails sees the semicolon and splits the query string into three separate parameters:
1. `keyed_param=abc`
2. `excluded_param=123`
3. `keyed_param=bad-stuff-here`

But now there is a duplicate `keyed_param`. This is where the second quirk comes into play. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final occurrence. The end result is that the cache key contains an innocent, expected parameter value, allowing the cached response to be served as normal to other users. On the back-end, however, the same parameter has a completely different value, which is our injected payload. It is this second value that will be passed into the gadget and reflected in the poisoned response.

This exploit can be especially powerful if it gives you control over a function that will be executed. For example, if a website is using JSONP to make a cross-domain request, this will often contain a `callback` parameter to execute a given function on the returned data:
`GET /jsonp?callback=innocentFunction`
In this case, you could use these techniques to override the expected callback function and execute arbitrary JavaScript instead.
Here is a lab that exploits this: [cache_parameter_parsing_quirks](labs/cache_parameter_parsing_quirks.md)

#### Exploiting fat GET support
In some cases, the HTTP method used may not be keyed. This can lead to scenarios where you poison the cache with a `POST` request and this poisoned cache affects the `GET` requests made by the users.

Although this scenario is pretty rare, you can sometimes achieve a similar effect by simply adding a body to a `GET` request to create a "fat" `GET` request:
```http
GET /?param=innocent 
HTTP/1.1 
… 
param=bad-stuff-here`
```
In this case, the cache key would be based on the request line, but the server-side value of the parameter would be taken from the body.
Here is lab that covers this topic: [cache_poisoning_fat_get_request](labs/cache_poisoning_fat_get_request.md)

#### Normalized cache keys
Any normalization applied to the cache key can also introduce exploitable behavior. In fact, it can occasionally enable some exploits that would otherwise be almost impossible.

For example, when you find reflected XSS in a parameter, it is often unexploitable in practice. This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them. The response that the intended victim receives will merely contain a harmless URL-encoded string.

Some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key:

`GET /example?param="><test> GET /example?param=%22%3e%3ctest%3e`

This behavior can allow you to exploit these otherwise "unexploitable" XSS vulnerabilities. If you send a malicious request using Burp Repeater, you can poison the cache with an unencoded XSS payload. When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing your unencoded payload.

As a result, the cache will serve the poisoned response and the payload will be executed client-side. You just need to make sure that the cache is poisoned when the victim visits the URL.
# How to prevent web cache poisoning vulnerabilities

The definitive way to prevent web cache poisoning would clearly be to disable caching altogether. While for many websites this might not be a realistic option, in other cases, it might be feasible. For example, if you only use caching because it was switched on by default when you adopted a CDN, it might be worth evaluating whether the default caching options really do reflect your needs.

Even if you do need to use caching, restricting it to purely static responses is also effective, provided you are sufficiently wary about what you class as "static". For instance, make sure that an attacker can't trick the back-end server into retrieving their malicious version of a static resource instead of the genuine one.

This is also related to a wider point about web security. Most websites now incorporate a variety of third-party technologies into both their development processes and day-to-day operations. No matter how robust your own internal security posture may be, as soon as you incorporate third-party technology into your environment, you are relying on its developers also being as security-conscious as you are. On the basis that you are only as secure as your weakest point, it is vital to make sure that you fully understand the security implications of any third-party technology before you integrate it.

Specifically in the context of web cache poisoning, this not only means deciding whether to leave caching switched on by default, but also looking at which headers are supported by your CDN, for example. Several of the web cache poisoning vulnerabilities discussed above are exposed because an attacker is able to manipulate a series of obscure request headers, many of which are entirely unnecessary for the website's functionality. Again, you may be exposing yourself to these kinds of attacks without realizing, purely because you have implemented some technology that supports these unkeyed inputs by default. If a header isn't needed for the site to work, then it should be disabled.

You should also take the following precautions when implementing caching:

- If you are considering excluding something from the cache key for performance reasons, rewrite the request instead.
- Don't accept fat `GET` requests. Be aware that some third-party technologies may permit this by default.
- Patch client-side vulnerabilities even if they seem unexploitable. Some of these vulnerabilities might actually be exploitable due to unpredictable quirks in your cache's behavior. It could be a matter of time before someone finds a quirk, whether it be cache-based or otherwise, that makes this vulnerability exploitable.