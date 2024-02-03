# What is OAuth?
 OAuth is an authorization framework that enables websites and web applications to use **resources from the user's account of other application**. 
 It is a delegated authorization, as an application asks another application to authorize it to obtain the resources of that user in the application.

In OAuth, the requesting application does not need to know the credentials of the user, as the authentication is delegated in the requested application.  
The basic OAuth process is widely used to integrate third-party functionality that requires access to certain data from a user's account. For example, an application might use OAuth to request access to your email contacts list so that it can suggest people to connect with. 

However, the same mechanism is also used to provide third-party authentication services, allowing users to log in with an account that they have with a different website. **Note that this is not the typical use for OAuth, as it should be used for authorization.**

# How does OAuth 2.0 work?
In OAuth 2.0, there are three entities: The client application, the resource owner and the service provider.
- **Client application** - The website or web application that wants to access the user's data.
- **Resource owner** - The user whose data the client application wants to access.
- **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an authorization server and a resource server.
## Most common OAuth process flow
There are numerous different ways that the actual OAuth process can be implemented. These are known as OAuth "flows" or "grant types". In this topic, we'll focus on the "authorization code" and "implicit" grant types as these are by far the most common. Broadly speaking, both of these grant types involve the following stages:

1. The **client application requests access** to a subset of the user's data, specifying which grant type they want to use and what kind of access they want.
2. The **user is prompted to log in to the OAuth service and explicitly give their consent for the requested access.**
3. The client application receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies significantly depending on the grant type.
4. **The client application uses this access token to make API calls fetching the relevant data from the resource server.**


# Exploiting OAuth as it is not for authentication
 OAuth was not designed for authentication, but most of the websites use it for authentication. 
 
For OAuth authentication mechanisms, the basic OAuth flows remain largely the same; the main difference is how the client application uses the data that it receives. From an end-user perspective, the result of OAuth authentication is something that broadly resembles SAML-based single sign-on (SSO). In these materials, we'll focus exclusively on vulnerabilities in this SSO-like use case.

OAuth authentication is generally implemented as follows:

1. The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. This could be the email address that is registered with their account, for example.
2. After receiving an access token, the client application requests this data from the resource server, typically from a dedicated `/userinfo` endpoint.
3. Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password.

The problem with this flow is that, when the user is authenticated in the resource server and ask for the user data, **the user could ask for any user data, instead of its data, and return the other user's data, therefore not authenticating itself but authenticating other user. That's why it's an authorization framework, not an authentication framework.**
Here is a lab that exploits OAuth authentication framework: [oauth_for_authentication](labs/oauth_for_authentication.md)

# Exploiting OAuth to perform CSRF
A lot of OAuth components are optional, but some of them are strongly recommended. One of them is the `state` parameter. This is a parameter that **should** contain a nonce, as it is something tied to the user's interaction when it initiates the OAuth flow.
This value is later passed back and forth between the client application and the OAuth service, as a form of CSRF token so nodoby can craft this flow. 

The problem is knowing the value of this parameter and also not attaching this parameter at all. That means that an attacker can initiate an OAuth flow before tricking an user's browser to completing it.

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.

Note that if the site allows users to log in exclusively via OAuth, the `state` parameter is arguably less critical. However, not using a `state` parameter can still allow attackers to construct login CSRF attacks, whereby the user is tricked into logging in to the attacker's account.
## Identifying OAuth authentication
Recognizing when an application is using OAuth authentication is relatively straightforward. If you see an option to log in using your account from a different website, this is a strong indication that OAuth is being used.

The most reliable way to identify OAuth authentication is to proxy your traffic through Burp and check the corresponding HTTP messages when you use this login option. Regardless of which OAuth grant type is being used, the first request of the flow will always be a request to the `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In particular, keep an eye out for the `client_id`, `redirect_uri`, and `response_type` parameters. For example, an authorization request will usually look something like this:
`GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 Host: oauth-authorization-server.com`

## How do OAuth authentication vulnerabilities arise?
OAuth [authentication vulnerabilities](https://portswigger.net/web-security/authentication) arise partly because the OAuth specification is relatively vague and flexible by design. Although there are a handful of mandatory components required for the basic functionality of each grant type, the vast majority of the implementation is completely optional. This includes many configuration settings that are necessary for keeping users' data secure. In short, there's plenty of opportunity for bad practice to creep in.

One of the other key issues with OAuth is the general lack of built-in security features. The security relies almost entirely on developers using the right combination of configuration options and implementing their own additional security measures on top, such as robust input validation. As you've probably gathered, there's a lot to take in and this is quite easy to get wrong if you're inexperienced with OAuth.

Depending on the grant type, highly sensitive data is also sent via the browser, which presents various opportunities for an attacker to intercept it.

# Recon
Doing some basic recon of the OAuth service being used can point you in the right direction when it comes to identifying vulnerabilities.

It goes without saying that you should study the various HTTP interactions that make up the OAuth flow - we'll go over some specific things to look out for later. If an external OAuth service is used, you should be able to identify the specific provider from the hostname to which the authorization request is sent. As these services provide a public API, there is often detailed documentation available that should tell you all kinds of useful information, such as the exact names of the endpoints and which configuration options are being used.

Once you know the hostname of the authorization server, you should always try sending a `GET` request to the following standard endpoints:
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

These will often return a JSON configuration file containing key information, such as details of additional features that may be supported. This will sometimes tip you off about a wider attack surface and supported features that may not be mentioned in the documentation.