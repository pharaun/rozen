Rozen

Have a chunk toward the end of the archive for ‘other reference’ where it describes the *other* archive files that contains an external to archive reference to assist with mapping/handling updates.  ie we hve a initial backup archive with all of the data chunks in it

then updates/delta archives afterward that has the changed bits + back-ref that lists where all of the older


Initial implement 
- all within one file and stream it out
- Allow for chunking of the file into pieces
- Allow for linking externally to other files
- Do s3 and remote file operations 


Maybe just have everything like key value data store with version we have a part number on everything and then treat things like this

This will permit multi chunk of various record types and it’ll be built in


Like k/v database handles multiple versions already. We can implement support for multiple parts 

One option for encryption could be to have encryption be per strata (segment) which would allow one key per segment file or something, which would help with inter-segment grain encryption issue.

Question then how to handle seeking to a specific spot in a segment, but that canbe a second layer of chunked encryption maybe? data points to (ie to this or that archives)
