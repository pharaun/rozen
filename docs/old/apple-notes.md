Rozen

Have a queue of parts, the storage system will deal with storing each piece, ie 100x10mb pieces per file on s3 for eg

That’s it’s only job. Take 10mb pieces and upload it to s3 then close an run of pieces and start a new one


Then in front there is like 2 system probs? One for larger than a piece objects ie (20+mb) this goes into its own large file queue to be compressed and encrypted and chopped up to be tossed into several pieces and sent to the queue

Then there’s the small files that gets collected and packed into a piece and then sent out to the piece queue








https://web.stanford.edu/~ouster/cs111-spring23/assign_logfs/

So I’ve struggled with how to handle multiple part objects

Maybe the solution is to have metadata where it’s 
- part hash
- File hash
- Part count (0…)

The issue then becomes encryption management, ie if we encrypt based off each part then you can scramble and reorder parts that compose a file, how do you prevent this?


Design
- Directory tree walker and include or exclude file
- Due to streaming if a file is selected need to hash it ahead which 2x I/o
- Archives that takes the hash and file stream and ingest it into archive
- Metadata for tracking file system and archive metadata
- The s3 cloud or disk or ssh backend for sending the data where it need to go
- A manager to know where the latest copy of various files are for ease of targeted restore 



