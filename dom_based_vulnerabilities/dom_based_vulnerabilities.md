# What is the DOM?
DOM, also called "Document Object Model" is a **hierarchical representation** of the elements on the page that the browser is seeing.

Websites can use JavaScript to manipulate the elements in the DOM (items and their properties).
DOM is not a problem, it is how websites work. They need a hierarchical representation for the objects and it is OK for DOM to exist. 
The problem is **how the DOM is being used.** 

When an application has JavaScript code that **takes an attacker-controllable value from the DOM, known as a DOM source, and passes it into a dangerous function, known as a sink**, the problem is there.

Let's see the flow between sinks and sources and see why it is dangerous. 

# Sources
A source is a **JavaScript property** that **accepts data that is potentially attacker-controlled**. 
An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. 
Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.
### Common sources
The following are typical sources that can be used to exploit a variety of taint-flow vulnerabilities:
`document.URL document.documentURI document.URLUnencoded document.baseURI location document.cookie document.referrer window.name history.pushState history.replaceState localStorage sessionStorage IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB) Database`
# Sinks
A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. 
For example, the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.
### Which sinks can lead to DOM-based vulnerabilities?
The following list provides a quick overview of common DOM-based vulnerabilities and an example of a sink that can lead to each one. For a more comprehensive list of relevant sinks, please refer to the vulnerability-specific pages by clicking the links below.

|DOM-based vulnerability|Example sink|
|---|---|
|[DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) LABS|`document.write()`|
|[Open redirection](https://portswigger.net/web-security/dom-based/open-redirection) LABS|`window.location`|
|[Cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation) LABS|`document.cookie`|
|[JavaScript injection](https://portswigger.net/web-security/dom-based/javascript-injection)|`eval()`|
|[Document-domain manipulation](https://portswigger.net/web-security/dom-based/document-domain-manipulation)|`document.domain`|
|[WebSocket-URL poisoning](https://portswigger.net/web-security/dom-based/websocket-url-poisoning)|`WebSocket()`|
|[Link manipulation](https://portswigger.net/web-security/dom-based/link-manipulation)|`element.src`|
|[Web message manipulation](https://portswigger.net/web-security/dom-based/web-message-manipulation)|`postMessage()`|
|[Ajax request-header manipulation](https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation)|`setRequestHeader()`|
|[Local file-path manipulation](https://portswigger.net/web-security/dom-based/local-file-path-manipulation)|`FileReader.readAsText()`|
|[Client-side SQL injection](https://portswigger.net/web-security/dom-based/client-side-sql-injection)|`ExecuteSql()`|
|[HTML5-storage manipulation](https://portswigger.net/web-security/dom-based/html5-storage-manipulation)|`sessionStorage.setItem()`|
|[Client-side XPath injection](https://portswigger.net/web-security/dom-based/client-side-xpath-injection)|`document.evaluate()`|
|[Client-side JSON injection](https://portswigger.net/web-security/dom-based/client-side-json-injection)|`JSON.parse()`|
|[DOM-data manipulation](https://portswigger.net/web-security/dom-based/dom-data-manipulation)|`element.setAttribute()`|
|[Denial of service](https://portswigger.net/web-security/dom-based/denial-of-service)|`RegExp()`|
# Flow between Sources and Sinks
Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session.

The most common source is the URL, which is typically accessed with the `location` object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. Consider the following code:
`goto = location.hash.slice(1) if (goto.startsWith('https:')) {   location = goto; }`

This is vulnerable to [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection) because the `location.hash` source is handled in an unsafe way. If the URL contains a hash fragment that starts with `https:`, this code extracts the value of the `location.hash` property and sets it as the `location` property of the `window`. An attacker could exploit this vulnerability by constructing the following URL:
`https://www.innocent-website.com/example#https://www.evil-user.net`

When a victim visits this URL, the JavaScript sets the value of the `location` property to `https://www.evil-user.net`, which automatically redirects the victim to the malicious site. This behavior could easily be exploited to construct a phishing attack, for example.

# How to prevent DOM-based taint-flow vulnerabilities
There is no single action you can take to eliminate the threat of DOM-based attacks entirely. However, generally speaking, the most effective way to avoid DOM-based vulnerabilities is to avoid allowing data from any untrusted source to dynamically alter the value that is transmitted to any sink.

If the desired functionality of the application means that this behavior is unavoidable, then defenses must be implemented within the client-side code. In many cases, the relevant data can be validated on a whitelist basis, only allowing content that is known to be safe. In other cases, it will be necessary to sanitize or encode the data. This can be a complex task, and depending on the context into which the data is to be inserted, may involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence.

For measures you can take to prevent specific vulnerabilities, please refer to the corresponding vulnerability pages linked from the table above.

# Controlling the web message source
In this section, we'll look at how web messages can be used as a source to exploit [DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) on the recipient page. We'll also describe how such an attack is constructed, including how common origin-verification techniques can often be bypassed.

If a page handles incoming web messages in an unsafe way, for example, by not verifying the origin of incoming messages correctly in the event listener, properties and functions that are called by the event listener can potentially become sinks. For example, an attacker could host a malicious `iframe` and use the `postMessage()` method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page. This behavior means that you can use web messages as the source for propagating malicious data to any of those sinks.

## What is the impact of DOM-based web message vulnerabilities?
The potential impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles the data in an unsafe way by passing it into a sink, then the joint behavior of the two documents may allow an attacker to compromise the user, for example.

## How to construct an attack using web messages as the source
Consider the following code:
`<script> window.addEventListener('message', function(e) {   eval(e.data); }); </script>`

This is vulnerable because an attacker could inject a JavaScript payload by constructing the following `iframe`:
`<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">`

As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into a sink, in this case, the `eval()` function.

## Origin verification
Even if an event listener does include some form of origin verification, this verification step can sometimes be fundamentally flawed. For example, consider the following code:
`window.addEventListener('message', function(e) { if (e.origin.indexOf('normal-website.com') > -1) { eval(e.data); } });`

The `indexOf` method is used to try and verify that the origin of the incoming message is the `normal-website.com` domain. However, in practice, it only checks whether the string `"normal-website.com"` is contained anywhere in the origin URL. As a result, an attacker could easily bypass this verification step if the origin of their malicious message was `http://www.normal-website.com.evil.net`, for example.

The same flaw also applies to verification checks that rely on the `startsWith()` or `endsWith()` methods. For example, the following event listener would regard the origin `http://www.malicious-websitenormal-website.com` as safe:

`window.addEventListener('message', function(e) { if (e.origin.endsWith('normal-website.com')) { eval(e.data); } });`

Here are labs that covers this topic: [dom_xss_using_web_messages](labs/dom_xss_using_web_messages.md)

# DOM-based open redirection

## What is DOM-based open redirection
DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation. For example, the following code is vulnerable due to the unsafe way it handles the `location.hash` property:

`let url = /https?:\/\/.+/.exec(location.hash); if (url) {   location = url[0]; }`

An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause a redirection to an arbitrary external domain.

**This is all because we can control the source, and it goes into a sink.**
## What is the impact of DOM-based open redirection?
This behavior can be leveraged to facilitate phishing attacks against users of the website, for example. The ability to use an authentic application URL targeting the correct domain and with a valid TLS certificate (if TLS is used) lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.

If an attacker is able to control the start of the string that is passed to the redirection API, then it may be possible to escalate this vulnerability into a JavaScript injection attack. An attacker could construct a URL with the `javascript:` pseudo-protocol to execute arbitrary code when the URL is processed by the browser.

We can see a lab of DOM-based open redirection: [dom_open_redirection](labs/dom_open_redirection.md)

