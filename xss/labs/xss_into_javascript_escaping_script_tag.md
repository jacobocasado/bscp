
This is the vulnerable line of code:
![](imgs/xss_into_javascript.png)

We can try to escape the `<script>` because we are on control of `searchTerms`:
![](imgs/xss_into_javascript-1.png)

We managed to scape by adding a `</script>` to the start of our payload and then adding our malicious script:
![](imgs/xss_into_javascript-2.png)![](imgs/xss_into_javascript-3.png)