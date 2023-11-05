DOM XSS in jQuery selector sink using a hashchange event.

The vulnerable piece of code is:
![](imgs/dom_xss_jquery_selector_hashchange.png)

Está leyendo el `location.hash` y está intentando autoscrollear a esa sección. Por ejemplo, si ponemos `open`, está cogiendo la primera entrada que encuentra que empiece así y nos autoscrollea a ella.
![](imgs/dom_xss_jquery_selector_hashchange-1.png)
Nos dice lo mismo el scanner de BurpSuite: ![](imgs/dom_xss_jquery_selector_hashchange-2.png)
![](imgs/dom_xss_jquery_selector_hashchange-3.png)
El cómo explotarlo es más complicado sin mirar la solución, y sinceramente he mirado el payload que me da BurpSuite:
![](imgs/dom_xss_jquery_selector_hashchange-4.png)
Efectivamente:
![](imgs/dom_xss_jquery_selector_hashchange-5.png)
Entiendo que hay que posicionar ahí el payload, pero no entiendo porque hay que cerrar con `'=>` al principio. **De hecho, lo he analizado y sólo hace falta poner '**, una sola comilla, para cerrarlo y funciona.



