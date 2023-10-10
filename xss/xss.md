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

An specific lab covers this:

