# What is clickjacking?
Clickjacking, also called UI redressing, is an **interface-based attack** in which an user is tricked into clicking an actionable content on a hidden website **by clicking on some other content in a decoy website**.

For example, an user accesses a decoy website by clicking an email URL and clicks on a button to win a prize. But, by clicking this button, he accepted to give the attacker money, as he clicked in an alternative hidden button that performs another operation. 
This is clickjacking, having a front actionable webpage containing **a hidden link, lets say, within an invisible iframe.** This iframe is on top on the user's content.

# Clickjacking vs CSRF
This attack is a bit "different" than the CSRF attack, as the user has to visit the page and also perform a **button click**, whereas the CSRF technique forges the request without any extra user input.
Protection against CSRF attacks is often provided by a CSRF token, specific to each session. The problem is that **clickjacking attacks** are not mitigated by this token as a target session is stablished with content loaded from an authentic website and with all requests happening on-domain. CSRF tokens are placed into requests, and passed to the server as if a normal session was happening (it is happening, but invisibly). The only difference between a normal session and a clickjacked session is that the process occurs within a hidden iframe.

# How to construct a basic clickjacking attack
Clickjacking attacks uses CSS to create and manipulate layers. The attacker **creates a website and uses CSS to deploy an invisible iframe with the target website overlaid on the decoy website.**

An example of a clickjacked website using the style tag and parameters is as follows:
```css
<head>
  <style>
    #target_website {
      position: relative;
      width: 128px;
      height: 128px;
      opacity: 0.00001;
      z-index: 2;
    }

    #decoy_website {
      position: absolute;
      width: 300px;
      height: 400px;
      z-index: 1;
    }
  </style>
</head> ... <body>
  <div id="decoy_website"> ...decoy web content here... </div>
  <iframe id="target_website" src="https://vulnerable-website.com"></iframe>
</body>
```

The idea is that the iframe of the target website is positioned within the browser so there is a **precise overlap of the target action with the decoy website using appropiate width and height position values.** Absolute and relative position values are to **ensure** that the target website accurately overlaps the decoy regardless the screen, browser and platform. 
The z-index parameter determines the **stacking order of the HTML elements, therefore, the target website uses a higher z-index to be placed on top of the decoy website**. 
The opacity parameter is nearly 0 in the target website, so that the iframe content is transparent to the user.
Why not 0? Well, browser clickjacking protection might apply **threshold-based iframe transparency detection** (for example, Chrome version 76 includes this behavior but Firefox does not). The attacker selects opacity values so that the desired effect is achieved without triggering protection behaviors.

Let's see a lab that uses clickjacking attack on a website that is protected against CSRF: [basic_clickjacking_bypassing_csrf_token](labs/basic_clickjacking_bypassing_csrf_token.md)

# Clickjacking with prefilled form input

Some websites that require form completion and submission permit prepopulation of form inputs using GET parameters prior to submission. Other websites might require text before form submission. As GET values form part of the URL then the target URL can be modified to incorporate values of the attacker's choosing and the transparent "submit" button is overlaid on the decoy site as in the basic clickjacking example.

This advanced lab covers clickjacking need a parameter that indicates the email of the user to delete (it is the same, but indicating the mail of the user that is going to be deleted in the URL): [clickjacking_with_input_in_url](labs/clickjacking_with_input_in_url.md).

# Frame busting scripts and how to bypass them
We can perceive that clickjacking attacks are only possible whenever websites **can be framed.** Therefore, a preventive technique is baes upon restricting the framing capability for the websites.

One common client-side protection enforced by the web browser is to use **frame busting or frame breaking scripts.** These are crafted scripts. The scripts can be implemented via browser JavaScript add-ons or extensions such as NoScript. Usually, these frame busting scripts are crafted to perform one of the following things:

- check and enforce that the current application window is the main or top window,
- make all frames visible,
- prevent clicking on invisible frames,
- intercept and flag potential clickjacking attacks to the user.

This way, the attacks are harder. to perform. These techniques are often **browser and platform specific,** and because of the flexibility of HTML, they can usually be circumvented by attackers.
As frame busters are JavaScript code then it is the browser decision to execute it. The browser's settings may prevent their operation or even the browser could not support JavaScript.

An effective workaround against frame busters is to use the **HTML5 frame** `sandbox` attribute in the elements.
When this attribute is set next to the `allow-forms` or the `allow-scripts` values and the `allow-top-navigation` value is omitted, the frame buster script can be **neutralized, as the iframe cannot check whether it is or not the top window, therefore, this functionality is bypassed.**

POC of iframe that could bypass a frame busting script using the sandbox tag with the allow-forms property:
`<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>`

This lab covers the clickjacking operation by using one of these frame busting script bypasses: [bypassing_frame_buster_script](labs/bypassing_frame_buster_script.md)

# Combining clickjacking with DOM XSS 
So far, we have looked at clickjacking as a self-contained attack, but this attack is even stronger when it is used as **a carrier for another attack such as a DOM XSS attack.** 
Implementation of this combined attack is relatively straightforward, assuming that the attacker has **first identified the XSS exploit**. Using the XSS exploit is combined with the iframe target URL so that **the user clicks on the button or link and executes the DOM XSS attack.**

Here is a lab that covers this combination of clickjacking to trigger DOM-based XSS: [clickjacking_to_trigger_dom_xss](labs/clickjacking_to_trigger_dom_xss.md)

# Multistep clickjacking attack
Sometimes attackers need to manipulate several steps for the attack to succeed. The typical multistep clickjacking attack would be **tricking a user to buy something from a retail website, for that, items need to be added to the shopping cart, then go to "cart" and place the order.**
These steps need to be chained with multiple divisions or iframe, and they need considerable precision and care from the attacker perspective if they are to be effective and stealthy.

Here is a lab that contains a multistep clickjacking attack: [multistep_clickjacking_attack](labs/multistep_clickjacking_attack.md)


# How to prevent clickjacking attacks

We have discussed a commonly encountered browser-side prevention mechanism, namely frame **busting scripts.** However, we have seen that it is **often straightforward for an attacker to circumvent these protections**. Consequently, **server driven protocols** have been devised that constrain browser iframe usage and mitigate against clickjacking.

Clickjacking is a browser-side behavior and its success or otherwise depends upon browser functionality and conformity to prevailing web standards and best practice. **Server-side protection against clickjacking is provided by defining and communicating constraints over the use of components such as iframes.** However, implementation of protection depends upon browser **compliance and enforcement of these constraints.** Two mechanisms for server-side clickjacking protection are **X-Frame-Options and [Content Security Policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy).**

## X-Frame-Options as a clickjacking defense
X-Frame-Options is an unofficial response header introduced in Internet Explorer 8 and nowadays used amongst all browsers.
The header provides the website owner the control over the use of iframes or objects so that the inclusion of a web page within **an iframe can be prohibited by the `deny` directive, like this:**
`X-Frame-Options: deny`

This is the same as saying: My website cannot be introduced in an iframe!

Alternatively, framing can be restricted to the same origin as website (this means that the visible website that is being visited can **host the same iframes of that website**) with the `sameorigin` directive: 
`X-Frame-Options: sameorigin`

There is a possibility of specifying a named website, just in case the developer wants to allow iframes from other websites to load with the `allow-from` directive:
`X-Frame-Options: allow-from https://normal-website.com`

X-Frame-Options is not implemented consistently across browsers (the `allow-from` directive is not supported in Chrome version 76 or Safari 12 for example). However, when properly applied in conjunction with Content Security Policy as part of a multi-layer defense strategy it can provide effective protection against clickjacking attacks.

## Content Security Policy (CSP) as a clickjacking defense
CSP, as seen in the XSS labs, is a **detection and prevention mechanism** that provides mitigation against these type of attacks too.
CSP is implemented **at server-side by a header of the form:** `Content-Security-Policy: policy`
The specified policy is a string of policy directives separated by semicolons.

The CSP provides the client browser information **about what permitted sources of web resources, so this way, the browser can see if resources from other side (that are not being specified in the CSP) are being loaded and act in consequence. **

The recommended clickjacking protection is to incorporate the `frame-ancestors` directive in the application's Content Security Policy. The `frame-ancestors 'none'` directive is similar in behavior to the X-Frame-Options `deny` directive. The `frame-ancestors 'self'` directive is broadly equivalent to the X-Frame-Options `sameorigin` directive. The following CSP whitelists frames to the same domain only:
`Content-Security-Policy: frame-ancestors 'self';`

Alternatively, framing can be restricted to named sites:
`Content-Security-Policy: frame-ancestors normal-website.com`

The following directive will only allow the page to be framed by other pages from the same origin:
`frame-ancestors 'self'`

The following directive will prevent framing altogether:
`frame-ancestors 'none'`

Using content security policy to prevent clickjacking is more flexible than using the X-Frame-Options header because you can specify multiple domains and use wildcards. For example:
`frame-ancestors 'self' https://normal-website.com https://*.robust-website.com`

CSP also validates each frame in the parent frame hierarchy, whereas `X-Frame-Options` only validates the top-level frame. **Using CSP to protect against clickjacking attacks is recommended.** You can also combine this with the `X-Frame-Options` header to provide protection on older browsers that don't support CSP, such as Internet Explorer.