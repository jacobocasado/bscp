# Lab description

The server in this lab manages the validation of the token with the public key in every situation, as the developers have specified to always use the public key to validate the signature of the token.
The idea is to change the token algorithm to HS256, a symmetric algorithm, and resign it with the public key of the server, once we have modified its content. the server will use the public key to validate the token, and, as we specified a symmetric algorithm, the verification will be successful.

Steps to pwn this lab:
1. Obtain a valid JWT.
2. Obtain the public keys of the server.
3. Modify the JWT.
4. Change the `alg` header to HS256.
5. Resign the token with the public key.
6. Send and profit

# Writeup
As always, let's obtain a valid JWT:
![[imgs/algorithm_confussion_bypass.png]]

Now, we have to get the public keys of the server. As specified in [Burp Suite section of this attack](https://portswigger.net/web-security/jwt/algorithm-confusion), the keys are usually in these sections:
- `/jwks.json`
- `/.well-known/jwks.json``

Visiting the first endpoints leads us to getting the public key of the server: 
![[imgs/algorithm_confussion_bypass-1.png]]
```
{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"f4bb312b-5b59-419d-bc51-775266075e71","alg":"RS256","n":"yy2cA6xW6rhhWKi0NHvCORmhf6XNV4_vuV4o5VkNEf0mphvQkICLpS63uCuw9gTW3sy8Mq_ZnrrOTkdPpAX1wvL2EN8vD2UcUPCAyI25PaBm8lciDrNOA4uA8HBVIsMMcwMB803CyJ179ktPXkjDKCZhASgxChQ-kA64FHySr6GCeBTTreH-JpgZ8zgNi6rF3vZF5WwMSLuROjQmfyqt64V3iGX4VsFbKetD2dyAoq3Gh3w0SF1hgClixqeIL-RvuvHVkvkS8bfuDPiDw3kaBADTD42QV4N9-rhM3El9guKTSf24S4jXV0vH5RTmKq-Bqoc2BfVxK5ZxHzbUueVvww"}]}
```

The next step is to create a **symmetric key using this parameters. Remember that we need to convert this public key used in RS256 into a symmetric key used in HS256**.
For that,there are several steps.
The first one, is to generate a **RSA key**, and copy the **KEY inside the JWK object. Do not copy the WHOLE JWK object, but the key!**
![[imgs/algorithm_confussion_bypass-2.png]]

Now, we have to get the PEM of this public key. For that, **right click in the key we have just created and click on "Copy public key as PEM"**":
![[imgs/algorithm_confussion_bypass-3.png]]

In the Decoder tab, paste this public key as PEM and base64 encode it:
![[imgs/algorithm_confussion_bypass-4.png]]

Now, create and generate a symmetric key. Replace the `k` value of this symmetric key for the base64 encoded key that we just generated:
![[imgs/algorithm_confussion_bypass-5.png]]

The last thing is to tamper the JWT to claim to be administrator, and specify HS256 as the algorithm, and signing the JWT with this key.
Let's do it:
![[imgs/algorithm_confussion_bypass-6.png]]
Sign the JWT with the symmetric key that comes from the public key of the server (don't modify the header):
![[imgs/algorithm_confussion_bypass-7.png]]

And sending the request retrieves a 200 OK by the server, meaning that is vulnerable to this attack:
![[imgs/algorithm_confussion_bypass-8.png]]

Just delete the user "carlos", as always.
![[imgs/algorithm_confussion_bypass-9.png]]

