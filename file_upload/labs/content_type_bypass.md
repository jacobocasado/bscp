The server just validates if the filetype declared in the `Content-Type` header is either JPG or PNG, but does not actually validate if the content of the uploaded file matches with this header. 
We can upload our malicious file and modify the `Content-Type` header of our file to match with JPG or PNG so the server just validates that, and accepts our file.

This is the file that we will try to upload:
`<?php echo file_get_contents('/home/carlos/secret'); ?>`
When uploading the file, we have the error:
![](imgs/content_type_bypass.png)

But we can just go to the request, and modify the content of the file type to one of those files:
![](imgs/content_type_bypass-1.png)

We changed it to image/jpeg, and forward the request:
![](imgs/content_type_bypass-2.png)

We can see that it now has been rendered. Let's make the server load the file by visiting our profile picture:
![](imgs/content_type_bypass-3.png)

The underlying request performed shows us the code:
![](imgs/content_type_bypass-4.png)