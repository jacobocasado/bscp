# What is Cross-Site Scripting (XSS)
XSS is a vulnerability that allows an attacker to compromise the interactions that users have with an application. This means that the normal interaction with the web application gets "poisoned" as it is possible to execute JavaScript code in the user's browser. 

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

- Perform any action within the application that the user can perform.
- View any information that the user is able to view.
- Modify any information that the user is able to modify.
- Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

XSS **circunvents the Same Origin Policy**. The Same Origin Policy or SOP, is a security mechanisms that restricts how a script or document loaded by one origin **can interact with a resource from other origin.**
Taking as source the [Mozilla Web Docs](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) , two URLs have the same origin if the **protocol, port and host are the same for both.** This avoid an attacker from www[.]attacker[.] using scripts that access www[.]facebook[.]com, as the request made to this last one site does not match with protocol, port and host. 
By executing XSS, the attacker can load arbitrary JavaScript code inside the vulnerable application and carry any actions that the user is able to perform, or gain control over the user's cookies.

![](imgs/cross-site-scripting.svg)

Remember that we always use an alert script, but we can load scripts from our hosted application and load them in the vulnerable application, changing the behavior. But it's very common to use the `alert` payload because it's short, harmless and hard to miss as it is a simple word.

**Note that I read [this](https://portswigger.net/research/alert-is-dead-long-live-print) article** and now I don't use `alert` as the main PoC for my tests, as some browsers like Google Chrome have disabled `alert` from cross-origin iframes. Now I use `print()`, as this just offers to print a simple page and it avoids confusion with browsers. If `print` works, your XSS works.

# The three types of XSS attacks
The three main types of XSS attacks are:
- **Reflected XSS**, where the script comes embedded in the HTTP request that the user performs.
- **Stored XSS**, where the script comes from the website's database and is loaded by the user when accessing the database by any means.
- **DOM-based XSS**, where the vulnerability exists in client-side code instead of server-side code.
## Reflected XSS
Reflected XSS is the simplest version of XSS and the application receives the XSS payload in the HTTP request.
A common example is inside an URL: 
`https://insecure-website.com/status?message=All+is+well. <p>Status: All is well.</p>`

Imagine that the application does not process the data, so an attacker could craft an attack like the following, embedding an script:
`https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script> <p>Status: <script>/* Bad stuff here... */</script></p>`

If the user visits the URL, the malicious script will trigger, in the **context of that user's session within the application. The script can carry out any action and retrieve any data to which the user has access.** 
Nevertheless, this attack is less severe than stored XSS as the attacks need to be embedded in the request that the user performs. In the stored XSS, the payload can be inside the webpage, and the user loads it when rendering the webpage, without the need of adding it in the URL.

This opens the first reflected XSS lab: [reflected_xss_without_encoding](labs/reflected_xss_without_encoding.md).
The second Reflected XSS lab is regarding most tags and atributes blocked: [reflected_xss_most_tags_and_attributes_blocked](labs/reflected_xss_most_tags_and_attributes_blocked.md)
The third lab is again about blocking some tags: [reflected_xss_html_all_tags_blocked](labs/reflected_xss_html_all_tags_blocked.md)

Sometimes we do not even need to escape the `attribute` value as that attribute is vulnerable. This happens, for example, if our context is inside an `href` tag, as we can use the `javascript` keyword to execute the script. For example:
`<a href="javascript:alert(document.domain)">`

### Reflected XSS on canonical link tag
You might encounter websites that encode angle brackets but still allow you to inject attributes. Sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag. You can exploit this behavior using access keys and user interaction on Chrome.
Access keys allow you to provide keyboard shortcuts that reference a specific element. The `accesskey` attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire. In the next lab you can experiment with access keys and exploit a canonical tag. [You can exploit XSS in hidden input fields using a technique invented by PortSwigger Research](https://portswigger.net/research/xss-in-hidden-input-fields).

There is a lab that covers this topic: [reflected_xss_canonical_link_tag](labs/reflected_xss_canonical_link_tag.md)

### Double backslash to avoid escaping single quote characters
Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash. A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator. In this situation, applications often make the mistake of failing to escape the backslash character itself. This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application.

For example, suppose that the input:
`';alert(document.domain)//`

gets converted to:
`\';alert(document.domain)//`

You can now use the alternative payload:
`\';alert(document.domain)//`

which gets converted to:
`\\';alert(document.domain)//`

Here, the first backslash means that the second backslash is interpreted literally, and not as a special character. This means that the quote is now interpreted as a string terminator, and so the attack succeeds.

This is the lab that covers this topic: [reflected_xss_double_escaping](labs/reflected_xss_double_escaping.md)

### Using HTML-encoding to bypass blocking or scaping
When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.

When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by HTML-encoding those characters.

For example, if the XSS context is as follows:
`<a href="#" onclick="... var input='controllable data here'; ...">`

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script:
`&apos;-alert(document.domain)-&apos;`

The `&apos;` sequence is an HTML entity representing an apostrophe or single quote. Because the browser HTML-decodes the value of the `onclick` attribute before the JavaScript is interpreted, the entities are decoded as quotes, which become string delimiters, and so the attack succeeds.

There is a lab that covers this topic: 
## Stored XSS
Stored XSS arises when an application receives data, saves it in the application and then renders that data in an unsafe way. Imagine a website with blog posts, that allows users adding comments.
An attacker could add a JavaScript payload as a comment and the JavaScript code will get rendered in all of the user's browsers that see the comment.

We have an example on the first Stored XSS lab: [stored_xss_without_encoding](labs/stored_xss_without_encoding.md)

## DOM-based XSS
DOM XSS arises when an application contains some **client-side JavaScript** that processes data from an untrusted source in an unsafe way, which is usually writing the data back to the DOM.

The attacker can control the source in which the data is obtained, such as the URL, and knows that this source goes into a sink that supports dynamic code execution, such as `eval` or `innerHTML`. The attack vector is to place a payload in a source **that you know that will visit a sink**, and therefore, gets executed.

The most common source is the URL, which is typically accessed with the `location` object. An attacker can construct a link to send a victim to a vulnerable page with a payload in the query string and fragment portions of the URL. Consider the following code:

`goto = location.hash.slice(1) if (goto.startsWith('https:')) {   location = goto; }`

This is vulnerable to [DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection) because the `location.hash` source is handled in an unsafe way. If the URL contains a hash fragment that starts with `https:`, this code extracts the value of the `location.hash` property and sets it as the `location` property of the `window`. An attacker could exploit this vulnerability by constructing the following URL:
`https://www.innocent-website.com/example#https://www.evil-user.net`
When a victim visits this URL, the JavaScript sets the value of the `location` property to `https://www.evil-user.net`, which automatically redirects the victim to the malicious site. This behavior could easily be exploited to construct a phishing attack, for example.

### How to test for DOM XSS
The majority of DOM XSS vulnerabilities can be found quicly using Burp Suite's web scanner. But to do it manually we would need a browser with developer tools, such as Chrome.
#### Testing HTML sinks
To test for DOM XSS in an HTML sink, place a random alphanumeric string into the source (such as `location.search`), then use developer tools to inspect the HTML and find where your string appears. Note that the browser's "View source" option won't work for DOM XSS testing because it doesn't take account of changes that have been performed in the HTML by JavaScript. In Chrome's developer tools, you can use `Control+F` (or `Command+F` on MacOS) to search the DOM for your string.

For each location where your string appears within the DOM, you need to identify the context. Based on this context, you need to refine your input to see how it is processed. For example, if your string appears within a double-quoted attribute then try to inject double quotes in your string to see if you can break out of the attribute.

Note that browsers behave differently with regards to URL-encoding, Chrome, Firefox, and Safari will URL-encode `location.search` and `location.hash`, while IE11 and Microsoft Edge (pre-Chromium) will not URL-encode these sources. If your data gets URL-encoded before being processed, then an XSS attack is unlikely to work.

#### Testing JavaScript execution sinks

Testing JavaScript execution sinks for DOM-based XSS is a little harder. With these sinks, your input doesn't necessarily appear anywhere within the DOM, so you can't search for it. Instead you'll need to use the JavaScript debugger to determine whether and how your input is sent to a sink.

For each potential source, such as `location`, you first need to find cases within the page's JavaScript code where the source is being referenced. In Chrome's developer tools, you can use `Control+Shift+F` (or `Command+Alt+F` on MacOS) to search all the page's JavaScript code for the source.

Once you've found where the source is being read, you can use the JavaScript debugger to add a break point and follow how the source's value is used. You might find that the source gets assigned to other variables. If this is the case, you'll need to use the search function again to track these variables and see if they're passed to a sink. When you find a sink that is being assigned data that originated from the source, you can use the debugger to inspect the value by hovering over the variable to show its value before it is sent to the sink. Then, as with HTML sinks, you need to refine your input to see if you can deliver a successful XSS attack.

**BUT, the Burp Suite extension called DOM invader is great for this cases as it does some research! We will try it to find DOM XSS**.

### Labs regarding DOM XSS
The first lab covering DOM XSS is the lab where `document.write` sink processes the `location.search` source: [dom_xss_location_search_document_write](labs/dom_xss_location_search_document_write.md)

The second lab of DOM XSS is an expansion of the first one in which the content that is write to the sink `document.write` includes some content that we need to take account of in the exploit. For example, closing some existing elements. This is seen in the following lab: [dom_xss_location_search_document_write_inside_select](labs/dom_xss_location_search_document_write_inside_select.md)

The third lab is about the `innerHTML` sink, which is more restrictive as it doesn't accept `script` elements on any modern browser, nor `svg onload` events. The idea is to use alternative mechanisms, like `img` or `iframe`. Event handlers such as `onload` and `onerror` can still be used in this payloads, as done with the `svg` payload. The lab that covers this `innerHTML` sink is the following: [dom_xss_location_search_inner_html](labs/dom_xss_location_search_inner_html.md)

The fourth lab includes a JavaScript library called `jQuery`, that also contains mechanisms to include modifications to our payload. In the following case, the `jQuery` `attr()` function can change the attributes of DOM elements. If it is possible to insert an user-controlled value in the `attr()` function, we can cause XSS.
For example, we have some JavaScript that uses this library and this method to change the `href` attribute of an element of the page with something specified in the URL:
```javaScript
$(function() { $('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl')); });
```

This is basically saying: "Hey, modify the value of backLink so its attribute `href` points to the new parameter specified in the URL, exactly the returnURL parameter." This parameter is in the URL, so XSS is here.
We can see that a new sink is introduced due to this new jQuery library.

An specific lab covers this: [dom_xss_jquery_attr_href_location_search](labs/dom_xss_jquery_attr_href_location_search.md)

Another potential sink when jQuery is being used is the selector function: `$()`. This sink is very common, and attacks with this selector and the `location.hash` source are present in a lot of pages.
The common behavior of using the selector function is to create animations or autoscrolling to particular element on the page. This behavior was often implemented using a `hashchange` event handler like the following:
`$(window).on('hashchange', function() { var element = $(location.hash); element[0].scrollIntoView(); });`

As the `hash` element is user controllable, an attacker can use this element to inject an XSS payload into the `$()` selector sink. **More recent versions of jQuery patch this vulnerability by preventing from injecting HTML into a selector when the input begins with a hash (`#`) character.** However, is still good to keep looking for this attack in old places.

The lab related to this vulnerability is: [dom_xss_jquery_selector_hashchange](labs/dom_xss_jquery_selector_hashchange.md)

Another framework that can be exploited is **AngularJS**. If AngularJS is used, it may possible to execute JavaScript without angle brackets or events. If using **AngularJS** a website uses `ng-app` attribute on an HTML element, this element will be processed by AngularJS. In that case, **AngularJS** will execute JavaScript code inside double curly braces.
A lab that covers this is the following: [dom_xss_angularjs_expresion](labs/dom_xss_angularjs_expresion.md)

## DOM XSS combined with reflected and stored data
Some pure DOM-based vulnerabilities are self-contained within a single page. If a script reads some data from the URL and writes it to a dangerous sink, the vulnerability is completely **client-side**.

However, sources aren't limited to data that is directly exposed by browser and can be also originated from the website, like the **HTML** response from the server. When this happens, the DOM XSS is combined and acts as a **Reflected DOM XSS.**
In a reflected DOM XSS vulnerability, the server processes data from the request, and echoes the data into the response. The reflected data might be placed into a JavaScript string literal, or a data item within the DOM, such as a form field. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink.
An example payload is the following:
`eval('var data = "reflected string"');`

A lab that covers this topic is the following: [dom_xss_reflected](labs/dom_xss_reflected.md)

Websites may also store data from the server and load that data as **a source** into a sink. In that case, we have a **stored DOM XSS** vulnerability. An example of this situation is when we find something like this:
`element.innerHTML = comment.author`

A lab that covers this topic is the following: [dom_xss_reflected](labs/dom_xss_reflected.md)
## Which sinks can lead to DOM-XSS vulnerabilities?

The following are some of the main sinks that can lead to DOM-XSS vulnerabilities:

`document.write() document.writeln() document.domain element.innerHTML element.outerHTML element.insertAdjacentHTML element.onevent`

The following jQuery functions are also sinks that can lead to DOM-XSS vulnerabilities:

`add() after() append() animate() insertAfter() insertBefore() before() html() prepend() replaceAll() replaceWith() wrap() wrapInner() wrapAll() has() constructor() init() index() jQuery.parseHTML() $.parseHTML()`

## XSS into JavaScript

When the XSS context is some existing JavaScript within the response, a wide variety of situations can arise, with different techniques necessary to perform a successful exploit.
### Terminating the existing script
In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript. For example, if the XSS context is as follows:

`<script> ... var input = 'controllable data here'; ... </script>`

then you can use the following payload to break out of the existing JavaScript and execute your own:
`</script><img src=1 onerror=alert(document.domain)>`
The reason this works is that the browser first performs HTML parsing to identify the page elements including blocks of script, and only later performs JavaScript parsing to understand and execute the embedded scripts. The above payload leaves the original script broken, with an unterminated string literal. But that doesn't prevent the subsequent script being parsed and executed in the normal way.
Lab that covers this topic: [xss_into_javascript_escaping_script_tag](labs/xss_into_javascript_escaping_script_tag.md)

### Breaking out of a JavaScript string

In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.

Some useful ways of breaking out of a string literal are:
`'-alert(document.domain)-' 
`';alert(document.domain)//``

Lab that covers this topic: [reflected_xss_javascript_string](labs/reflected_xss_javascript_string.md)

### XSS in JavaScript template literals

JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the `${...}` syntax.

For example, the following script will print a welcome message that includes the user's display name:
``document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;``

When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the `${...}` syntax to embed a JavaScript expression that will be executed when the literal is processed. For example, if the XSS context is as follows:
``<script> ... var input = `controllable data here`; ... </script>``

then you can use the following payload to execute JavaScript without terminating the template literal:
`${alert(document.domain)}`

There is a lab that covers this topic:


# Exploiting XSS is not about generating alerts
A lot of new people think that exploting XSS means generating an alert box, but this is just the best PoC for our tests. In reality, what we want to do is **to execute JavaScript** code in another domain that is not ours, therefore, bypassing the Same Origin Policy as our malicious script is being executed in the another domain.

## Exploiting XSS to steal cookies
A real usage of XSS is to **steal cookies**. As the script is being executed on other domain, we can extract the cookies of the user that is executing the script. Then, we can use those cookies to impersonate the victim.

In practice, this approach has some significant limitations:
- The victim must be logged in.
**- Many applications hide their cookies from JavaScript using the `HttpOnly` flag. This way, cookies are not sent in scripts, as they are included only in HTTP requests.**
- Sessions might be locked to additional factors like the user's IP address, and not only the cookie value.
- The session might time out before you're able to hijack it.

Anyways, here is a lab that covers this topic: [xss_cookie_steal](labs/xss_cookie_steal.md)

## Exploiting XSS to capture passwords
These days, a lot of users have password managers that auto-fill their passwords. We can create a script like a formulary, with a password input, and let browsers autofill this input with the user's password (as the script is in the same domain, the browser thinks that it is a normal password field and autofills the password). This technique avoids the problem with stealing cookies, and allows us to know the password of the user to be able to use it in other platforms. 

The disadvantage is that if the user has 2FA, we can't bypass it as we do it with the cookie steal (as we are inside a **stablished session**). With password usage we have to create a new one.

There is a lab that covers this topic: [xss_password_steal](labs/xss_password_steal.md)

## Exploiting XSS to perform CSRF
Anything a legitimate user can do on a site, can be done with our malicious script. As we have user's context, as cookies, and also can extract the CSRF tokens as we are inside the domain, we **bypass CSRF** with XSS.
Some websites, for example, allow changing the user's password without specifying the current password. **In that case, if we get an XSS, we can create a malicious script to change the user's password and then access the user's account with the new password.**

Note to remember: Anti-CSRF strategies do not provide any protection if XSS is also present.

Here is a lab that covers this topic: [xss_csrf](labs/xss_csrf.md)
