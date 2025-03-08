Dynamodb backup

Could have 2 system option. One is a dynamodb for shared host backup. One is
SQLite for one host backup

And on program startup it checks if the local cache is recent enough otherwise
fetch latest copy from s3

Use it and update it then push new copy to s3 with verification seal on it

Same deal with dynamodb but can be done via multiple hosts maybe
