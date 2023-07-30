
# What is access control

Access control is the same word as **authorization**. As an easy to understand phrase, it is the application of contrainsts on **who or what can perform actions or access resources they have requested**. 

In the context of web applications, access control depends on authentication and session management, as, one is authenticated, and then, its rights are based depending on the username that has been authenticated.

To differentiate authentication to session management to access control:

- Authentication is **claiming who the user says to be. Demonstrating it.**
- Session management is a mechanism to identify that the subsequent HTTP requests are made by that user **without the user having to authenticate in each request. That is why sessions exist, to avoid the authentication on each granular request.**
- Access control (**this topic**) determines **whether the user that has been already authenticated (or not, e.g., an anonymous user)** is allowed to perform the action.

# Why are we talking about access controls
We talk about access controls because they are common to be exploited, and do often offer critical security vulnerabilities. Design of access controls is complex, and they are made by humans. Sometimes, when designing an access control, the technology used is not known, and therefore, errors are made.

Access controls are usually divided into three categories, **from an user perspective. We will talk about all three: Vertical access controls, Horizontal access controls and context-dependent access controls.**

## Vertical access controls
Vertical access controls are a mechanism to **restrict access to a functionality that is not available for X type of user.** Therefore, each type of user has access to a different function of the application, similar to roles. The "admin" role can delete and create accounts, but the "accounting" role cannot do it. Vice-versa, the "accounting" member can create/see bills, but the "admin" account might not. **Separation of duties and least privilege fine-grained implementations of security models that use vertical access controls.**

## Horizontal access controls
Horizontal access controls are mechanisms that restricts access to resources **to the users that are specifically allowed to access to those resources. This means that the resource is bound to a certain user or group of users, for example, a bank account. A bank account is unique to each user, and all of the users have the same role., and the same "rights"", but each user can see ITS own account**. That is an horizontal access control.

## Context-dependent access controls
As the name says, this type of access control restrict access to functionality and resources based **upon the state of the application OR the user's interaction with it.** For example, an user cannot modify the content of their cart **after paying for it, but they can do it before paying for it.** Same user, same privileges, but the context changes and therefore the rights associated to the user change.

# Attacks to broken access controls
We will talk to attacks to broken access controls, in which an user can access to a resource/perform some action that they **are not supposed to.**

## Vertical privilege escalation
This is the basic intention of an attacker: perform any functionality that they are not allowed to access. For example, if a non-administrative user can in fact gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

### Unprotected functionality
This is very basic, but sometimes works. This type of privilege escalation occurs when the functionality is basically unprotected, like binding the administration pannel to a "hidden" URL. An attacker could access to that "admin" URL that is hidden and obtain the same functionality as the real administrator, as there is not access control applied. 

For example, a website might host sensitive functionality at the following URL:
`https://insecure-website.com/admin`

#### Unprotected admin functionality with predictable URL
This might in fact be accessible by any user, not only administrative users who have a link to the functionality in their user interface. In some cases, the administrative URL might be disclosed in other locations, such as the `robots.txt` file:
`https://insecure-website.com/robots.txt`

**Even if the URL isn't disclosed anywhere, an attacker may be able to use a wordlist to brute-force the location of the sensitive functionality.**

Lab that covers this topic: [labs/unprotected_admin_functionality](labs/unprotected_admin_functionality.md)

#### Unprotected admin functionality with non-predictable URL
In some cases, sensitive functionality is not robustly protected, but does have a non-predictable URL. This concept is called **security by obscurity, as hiding this functionality (obscurity) does not provide access control since users might still discover the obfuscated URL in various ways.*

For example, imagine that an application hosts administrative functions at this URL:
`https://insecure-website.com/administrator-panel-yb556`

This might not be guessable by an attacker, but **the application might leak this URL to the users and that's it.** Examining the code of the application can be another vector to find these obscure endpoints.
Lab that covers this topic: [labs/unprotected_admin_functionality_unpredictable_url](labs/unprotected_admin_functionality_unpredictable_url.md)

### Parameter-based access control methods
In this case, there is an applied access control method. In some cases, applications check the user's right at login and then store this **information in an user-controllable location, as a cookie, request field, header, or preset query string parameter.**

This behavior causes that user can control these parameters and then gain access to the functionality which they are not authorized. 

#### Simple query string parameter
One of the basic examples is applying a parameter-based access control in a URL:
`https://insecure-website.com/login/home.jsp?admin=true
`https://insecure-website.com/login/home.jsp?role=1`

Sounds familiar to you?
Lab that covers this topic: [labs/user_role_controlled_by_request_parameter](labs/user_role_controlled_by_request_parameter.md)

#### Modifying the user role in the profile
Sometimes, the user role is well limited but it can be modified without authorization (or bypassing it) in the profile. Always look for the endpoint to change privileges, as, if it is weak, it will **literally break all the access controls as you can give any privilege you want.**

Lab that covers this topic: [labs/user_role_modification_in_user_profile](labs/user_role_modification_in_user_profile.md)

### Platform misconfiguration broken access controls
Some applications enforce access controls at the **platform layer**, by restricting access to specific URLs and HTTP methods based on the user's role. 

For example, an application can configure the rules like the following:
`DENY: POST, /admin/deleteUser, managers`
This means that the user CANNOT perform a POST request to the URL /admin/deleteuser for users in the managers group. **A lot of things can go wrong in this situation and often lead in access control bypasses**.

#### HTTP headers access control bypass
For example, some application frameworks support various **non-standard HTTP headers that can be used to overwrite the URL in the original request**. For example, the `X-Original-URL` and `X-Rewrite-URL` parameters overwrite the original URL request. You might think that the previous method that restricts access via the URL, can be bypassed by adding this headers to overwrite the URL and bypass the access control! Here is an example:

```
POST / HTTP/1.1 X-Original-URL:
/admin/deleteUser 
...
```

Instead of performing the following (which will be blocked by the rule `DENY: POST, /admin/deleteUser, managers` )
```
POST /admin/deleteUser HTTP/1.1
...
```

Both do the same action if the header is accepted by the application, but one bypasses the access control :)

Lab that covers this topic: [labs/url_rewrite_bypass](labs/url_rewrite_bypass.md)

#### HTTP methods access control bypass
In the last case, we added a header that overwrites the URL. But an alternative attack can arise in relation to the **HTTP method** used in the request. Some websites are tolerant to alternate HTTP request methods when performing an action.
If an attacker can use another method to perform actions on a unrestricted URL, they can bypass the access control implemented at platform layer.

Lab that covers this topic: [http_method_bypass](labs/http_method_bypass.md)

## Horizontal privilege escalation
Horizontal privilege escalation arises when a user is able to **gain access to resources belonging to another user, instead of their own resources. But, as it is horizontal, it means that the user that the attacker tries to get can have the same (or less) privileges than the real user. This is the difference from vertical (scale) to horizontal (target other users)*.

### Horizontal privesc changing user ID in request parameter
Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. For example, a user might ordinarily access their own account page using a URL like the following:

`https://insecure-website.com/myaccount?id=123`

Now, if an attacker modifies the `id` parameter value to that of another user, then the attacker might gain access to another user's account page, with associated data and functions.

Lab that covers this topic: [horizontal_privesc_user_id_in_request](labs/horizontal_privesc_user_id_in_request.md)

### Horizontal privesc changing unpredictable user ID in request parameter
There are some times that the user ID is unpredictable, but we know that the parameter is exploitable. For example, instead of attaching the name of the user, like in the last case, it can be a GUID. Therefore, it can be hard to detect/craft the GUID of another user. 

But, sometimes, this GUID can be obtained in the source code of the app, or in another section of the app that uses the GUID for other things and can be visualized. The idea is to search for the GUID in another section, and then, once the GUID is obtained, craft the request just as before.

Lab that covers this topic: [labs/horizontal_privesc_unpredictable_user_id_in_request](labs/horizontal_privesc_unpredictable_user_id_in_request.md)

### Horizontal privesc via user ID controlled by request with data leakage in redirect
Sometimes, the application detects if the user is not allowed to access the resource and performs a redirect to the login page. **But in this redirect, the user information is leaked, so inspecting the 302 response, we can see the user information in the body (leaked), so the attack is still valid. ** 

Lab that covers this topic: [labs/user_role_controlled_by_request_parameter_redirect_leakage](labs/user_role_controlled_by_request_parameter_redirect_leakage.md)

## Horizontal to vertical privilege escalation
Most of the times, an horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. Using the techniques of horizontal privesc targeting an admin, we can get administrative privileges.

For example, an attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:

`https://insecure-website.com/myaccount?id=456`

If the target user is an application administrator, then the attacker will gain access to an administrative account page. This page might disclose the administrator's password or provide a means of changing it, or might provide direct access to privileged functionality.

Lab that covers this topic: [horizontal_to_vertical_privesc](labs/horizontal_to_vertical_privesc.md)

## IDOR (Insecure Direct Object References)

### What are IDOR?
IDORs are a **specific type of access control vulnerability that arises when an application uses user-supplied input to access objects directly.**

IDOR was a name that appeared and was popular in OWASP 2007 Top Ten, and it is a good example of how access controls can be bypassed and circumvented.
IDOR vulnerabilities are often related to **horizontal privesc, but they can lead to vertical privesc, too, as we saw before.**

### IDOR examples
There are a few examples of IDOR, let's see the most importants.

### IDOR with direct reference to database objects
Let's consider a website that uses this URL to access the account of the customers and retrieve information of the database:
`https://insecure-website.com/customer_account?customer_number=132355`

The customer number is used **directly as the record index in queries that are processed in the backend.** If there are not other controls, or if they are weak, an attacker could modify the `customer_number` parameter and view the records of other customers. This is clearly an horizontal privesc. Again, if the targeted user has higher privileges, the attack can lead to privilege escalation.

### IDOR with direct reference to static files 
This is the typical IDOR, when resources are located in static files on the server-side filesystem. For example, a chat with diferent conversations at the urls:
`https://insecure-website.com/static/12144.txt`

An attacker could just modify the filename to retrieve another conversation created by another user.

Lab that cover IDORs: [insecure_direct_object_references](labs/insecure_direct_object_references.md)

## Access control vulnerabilities in multi-step processes
A lot of web sites implement important functions over a **series of steps.** This is usually done where a variety of user inputs or options need to be captured, or when **the user needs to review and confirm details before performing an action.**

A good example of a multi-step process would be this function to update the user details:
1. Load form containing details for a specific user.
2. Submit changes.
3. Review the changes and confirm.

Maybe, the first step is covered, or some of them, but having a multi-step process means that each of the steps **must be secure. If we find any flaw in any of the steps, we can break the whole process.**

For example, if an application just verifies user input and access on the first step of the three, an attacker could even bypass the first two steps, and go straight to the third step. As there is no verification, the process is completed and the attacker gains access.

Let's see this in a lab: [multi-step_process_access_control_vulns](labs/multi-step_process_access_control_vulns.md)

## Referer-based access control vulnerabilities
Some websites base its access controls in the `Referer` header submitted in the HTTP request. The `Referer` header is a header to tell the servers the previous page where the request was initiated. For example, if we are in Instagram and we clink a link to Google, the `Referer` header to the first request to Google will indicate `Instagram`, as we come from there.

This can lead to big problems, as this **is a header, so it is user-input.** An user could modify it to bypass access controls.

For example, suppose an application robustly enforces access control over the main administrative page at `/admin`, but for sub-pages such as `/admin/deleteUser` only inspects the `Referer` header. If the `Referer` header contains the main `/admin` URL, then the request is allowed.
In this situation, since the `Referer` header can be fully controlled by an attacker, they can forge direct requests to sensitive sub-pages, supplying the required `Referer` header, and so gain unauthorized access.

Lab that covers this topic: [access_control_bypass_via_referer_header](labs/access_control_bypass_via_referer_header.md)

## Access control bypass via Location header
Some web sites enforce access controls over resources based on the user's geographical location. This can apply, for example, to banking applications or media services where state legislation or business restrictions apply. These access controls can often be circumvented by the use of web proxies, VPNs, or manipulation of client-side geolocation mechanisms.

This is similar to [Referer-based access control vulnerabilities](#Referer-based%20access%20control%20vulnerabilities), where modifying this header can lead to bypasses due to the localization.

# How to prevent access control vulnerabilities
Access control vulnerabilities can generally be prevented by taking a defense-in-depth approach and applying the following principles:

- Never rely on obfuscation alone for access control.
- Unless a resource is intended to be publicly accessible, deny access by default.
- Wherever possible, use a single application-wide mechanism for enforcing access controls.
- At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.
- Thoroughly audit and test access controls to ensure they are working as designed.

Just ensure all the time, don't take anything for granted and verify, verify, verify.