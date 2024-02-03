We first need to see the cache oracle, the home page has a cache header, which tells us that probably this is a cache oracle:
![](imgs/cache_query_string.png)

Let's find one header that is a cache buster (that affects in the cache). We can see that the `Origin` header is a cache buster. More than that, when the `x-Cache` is a `miss`, we get the parameters that we include in the URL reflected:
![](imgs/cache_query_string-1.png)

Indeed, we can perform a XSS attack inside the reflected area if we do the following payload:
`'/><script>alert(1)</script>`
Therefore, we just have to add a parameter in the request so the cache gets poisoned: 
![](imgs/cache_query_string-2.png)
Now, delete the Origin header as we want to match the cache key of the normal user, that won't specify any origin:
![](imgs/cache_query_string-4.png)

Now, the payload is being reflected and let's try it, as a normal user, refresh the home page:
![](imgs/cache_query_string-3.png)