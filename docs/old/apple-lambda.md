Rozen

Fargate is cheaper than lambda, will need to have glue logic such as sqs -> lambda -> start up a fargate container for processing 

Will need to compare the cost to ie sqs -> lambda -> do logic in s3

Another option is S3 Batches, need to look at how it works exactly. Would prefer to have as much of my server side code be as generic so that it can work in other contexts such as a ssh service or other s3 api services


Anyway current options/current approach to help control and preserve the WORM semantics is to have two or more bucket or separate key/path to a s3 bucket

A incoming bucket/path where clients build their archive, signs it and refer to data in the cold-storage area

Then sqs watch for that and spins up a lambda to validate the signature and any other metadata needed. Once it has, then it can move that data into cold storage which the client only has a read(?) access to

This will prevent overwrites of the cold store from ransom ware and can setup MFA delete for cold storage. Main catch is you need to MFA delete for whole bucket or not so having a separate bucket may be the correct answer

Once the cold storage is in a good known state the lambda can then purge the incoming bucket

Also the incoming bucket can have read and write and modify semantics for the client which may permit the use case of streaming the backup archive to s3 then renaming it to its key/hash id before having the lambda move it.

Then depending on logic could have two wrapper one s3 and one ssh to support both use cases 

This would permit a privileged service in s3 to do additional processing as needed for backup integrity. But due to client signing and encrypting the data the server won’t be able to do much with the data outside of moving it and renaming it or something

Need to make sure to clamp the number of lambda workers to 1 or something and have a worker that possibly clean out bad data in the inbox to prevent wallet attacks


So we want to have each pack file having a hash. Of the content of the pack file in a merkle tree like thing

So one option is to save locally the rename of the pack files and then once you “finalize”
The snapshot you send up a list of pack files to rename and then the system that does batch move of these items from the original location in s3 to the WORM only location can also rename the pack files concurrently
