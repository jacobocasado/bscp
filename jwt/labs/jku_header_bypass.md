# Lab description
This lab covers the [[bscp/jwt/main#Injecting self/signed JWTs via the "jku" parameter]] section.

The idea is to craft a endpoint that contains a JSON with the public key that is used to verify the JWT, and resign the token with its corresponding private key. Then, adding the `jwu` extension to the JWT, the server will try to fetch from our server the public key, retrieve it, and verify if the sign is valid. This happens because **the server does not check the source of the jws, and trusts it.**

# Writeup

First, as always, log in as `wiener:peter` and get a valid JWT:
![[jwu_header_bypass.png]]

Send this request to the repeater and try to access the administrator user. It won't be possible as the token is not valid for that user:
![[jwu_header_bypass-1.png]]

Let's generate a RSA key pair, in the "JWT Editor Keys" section of Burp Suite:
![[jwk_header_bypass-1.png]]
![[jwk_header_bypass-2.png]]

Now, go to the exploit server and replace the "Body" section with the following JWK set, which will be empty by now:
`{ "keys": [ ] }`
![[jwu_header_bypass-2.png]]

Back in the JWT Editor Keys section, right click in the RSA key and click on "Copy public key as JWK" to get the key in JSON format (this will be what the server expects to fetch when checking the URL):
![[jwu_header_bypass-6.png]]

Now, update the content of the exploit server with this new JSON:
![[jwu_header_bypass-7.png]]

Now, the server hosts the public key.
We have to change the header to specify the endpoint where this public key is, by adding a `jws` parameter in the header, and also **changing the `kid` parameter of the header to match the one of the RSA key.** Lastly, replace the user to "administrator" in the payload. 
![[jwu_header_bypass-10.png]]

We need to sign the JSON finally with the RSA key, but it is important to **select the "Don't modify header" option**:
![[jwu_header_bypass-11.png]]

> When redoing the lab, I noticed that I could solve the lab by choosing the "Update/generate "alg", "typ" and "kid" parameters and this makes the "kid" parameter to be updated automatically and the resulting JWT is also valid. IDK why Burp Suite tells to select the first option to sign, but OK.

Sending the request once the JWT is signed gives us a 200 OK to access the /admin panel:
![[jwu_header_bypass-12.png]]

Lastly, delete the user "carlos":
![[jwu_header_bypass-13.png]]




