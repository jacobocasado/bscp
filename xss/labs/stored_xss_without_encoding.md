Base version of Stored XSS.
We have the website that allows us adding comments in posts (hmm, they get stored and then displayed):
![](imgs/stored_xss_without_encoding-1.png)
![](imgs/stored_xss_without_encoding-2.png)

This gets publicly displayed, so we can append a JavaScript payload and see if it gets rendered:
![](imgs/stored_xss_without_encoding-3.png)

Now, each time we load the page of comments, the script gets rendered:
![](imgs/stored_xss_without_encoding-4.png)




