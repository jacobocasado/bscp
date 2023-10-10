DOM XSS with `location.search` as the sink, and loads the payload on `document.write`:

![](imgs/dom_xss_location_search_document_write.png)

We can see that there is a `document.write` that is not sanitizing the code.
Let's craft an XSS payload to close the `img src`, which for that we only need to close the variable referenced by `src` the `<img`, so our payload should start with `">` and then add our payload:
`"><script>alert(1)</script>`

![](imgs/dom_xss_location_search_document_write-1.png)

Note that they use another payload instead of `script`, and this may be because `script` might not work. They use an `svg` payload: `"><svg onload=alert(1)>`

