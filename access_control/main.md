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

Lab that covers this topic: [[unprotected_admin_functionality]]

#### Unprotected admin functionality with non-predictable URL
In some cases, sensitive functionality is not robustly protected, but does have a non-predictable URL. This concept is called **security by obscurity, as hiding this functionality (obscurity) does not provide access control since users might still discover the obfuscated URL in various ways.*

For example, imagine that an application hosts administrative functions at this URL:
`https://insecure-website.com/administrator-panel-yb556`

This might not be guessable by an attacker, but **the application might leak this URL to the users and that's it.** Examining the code of the application can be another vector to find these obscure endpoints.
Lab that covers this topic: [[unprotected_admin_functionality_unpredictable_url]]

### Parameter-based access control methods
In this case, there is an applied access control method. In some cases, applications check the user's right at login and then store this **information in an user-controllable location, as a cookie, request field, header, or preset query string parameter.**

This behavior causes that user can control these parameters and then gain access to the functionality which they are not authorized. 

#### Simple query string parameter
One of the basic examples is applying a parameter-based access control in a URL:
`https://insecure-website.com/login/home.jsp?admin=true
`https://insecure-website.com/login/home.jsp?role=1`

Sounds familiar to you?
Lab that covers this topic: [[user_role_controlled_by_request_parameter]]

#### Modifying the user role in the profile
Sometimes, the user role is well limited but it can be modified without authorization (or bypassing it) in the profile. Always look for the endpoint to change privileges, as, if it is weak, it will **literally break all the access controls as you can give any privilege you want.**

Lab that covers this topic: [[user_role_modification_in_user_profile]]

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

Lab that covers this topic: [[url_rewrite_bypass]]

#### HTTP methods access control bypass
In the last case, we added a header that overwrites the URL. But an alternative attack can arise in relation to the **HTTP method** used in the request. Some websites are tolerant to alternate HTTP request methods when performing an action.
If an attacker can use another method to perform actions on a unrestricted URL, they can bypass the access control implemented at platform layer.

Lab that covers this topic:




## Horizontal privilege escalation

#### Simple query string parameter, with unpredictable user IDs
There are some times that the user ID is unpredictable, but we know that the parameter is exploitable. For example, instead of attaching the name of the user, like in the last case, it can be a GUID. Therefore, it can be hard to detect/craft the GUID of another user. 

But, sometimes, this GUID can be obtained in the source code of the app, or in another section of the app that uses the GUID for other things and can be visualized. The idea is to search for the GUID in another section, and then, once the GUID is obtained, craft the request just as before.

Lab that covers this topic: [[user_role_controlled_by_request_parameter_unpredictable_parameter]]

#### Simple query string parameter, with data leakage in redirect
Sometimes, the application detects if the user is not allowed to access the resource and performs a redirect to the login page. **But in this redirect, some information can be leaked which can be useful to attack the user, so the attack is still valid. **

Lab that covers this topic: [[user_role_controlled_by_request_parameter_redirect_leakage]]

### 
