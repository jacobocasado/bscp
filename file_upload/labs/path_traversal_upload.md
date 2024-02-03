If we upload the file like always, we can:
![](imgs/path_traversal_upload.png)

But, when visiting the file, it is not executed:
![](imgs/path_traversal_upload-1.png)

We need to upload the file in a different place. As a tip in the labs, web servers often use the `filename` field in `multipart/form-data` requests to determine the name and location where the file should be saved. 

Let's modify that field when uploading the file:
![](imgs/path_traversal_upload-2.png)

But we can see that the file is uploaded in the same route:
![](imgs/path_traversal_upload-3.png)

We might have to encode the file. Let's URL encode the file:
![](imgs/path_traversal_upload-4.png)

And now visit it:
![](imgs/path_traversal_upload-5.png)

Lab solved.

