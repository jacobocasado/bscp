
# Lab description

lab consists in:
1. Obtaining a valid JWT
2. Cracking this JWT with the BSCP wordlist to obtain the secret key, that is intendedly weak.
3. Using this secret key to craft our JWT of "administrator".

# Writeup

First, let's login as the user `wiener:peter`, as always. This gives us a valid JWT:
![[imgs/weak_signing_key.png]]

This JWT is indeed signed:
![[imgs/weak_signing_key-1.png]]

Let's copy the raw JWT into a file and inserting it into hashcat using the given wordlist. The hashcat command is the following, also mentioned in [[../main#Bruteforcing JWT signature using Hashcat]]:
`hashcat -a 0 -m 16500 <jwt> <wordlist>`

After a minute, we get the secret:

![[imgs/weak_signing_key-2.png]]

Well, just use this secret to craft the signature, and change the user to "administrator". Both things can be done in the JWT extension. Let's see if this works:
![[imgs/weak_signing_key-3.png]]

We can see that it works indeed! let's go to the section to delete users:
![[imgs/weak_signing_key-4.png]]

And delete the user "carlos":
![[imgs/weak_signing_key-5.png]]




