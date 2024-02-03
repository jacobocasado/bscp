
First, we have to retrieve the column that is being displayed. For that, we just use the technique to append a random string on each of the columns and check which string is being reflected.

By testing a bit, we know it's the second column:
![](imgs/sqli_retrieving_multiple_values_in_single_column.png)

Doing this in the first column returns us an error.
So we know the first column must be a NULL. 
In the second column we append `username||'~'||password` to get both columns' information in one column.
![](imgs/sqli_retrieving_multiple_values_in_single_column-1.png)

We can see that this information is being displayed in the same column.
![](imgs/sqli_retrieving_multiple_values_in_single_column-2.png)