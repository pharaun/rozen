Rozen backup

Define what you want with worm.
1. Separation of data and metadata
2. Metadata can vary but the raw data remains same 
3. When metadata changes, back that up, but when data change:
4. Is it new? Back it up
5. Is it changed? Warm and ask if want to restore or back up
6. Is metadata? Back that up
7. Detect when metadata changes like file being relocated and renamed

Also have management functions
1. validate local or backup archives are identical 
2. Detect changes and offer to restore
3. (Probs want to have optional but not by default changes being added)
4. (Same with delete where it’s recorded but the data remains saved?


Then see how the WOrM requirement works with other archives. And see how we can structure things in a generic way.

My initial reaction is to just make a new archive with everything in it each time. But for worm backups that’s wasteful so do want to at least support metadata upsates

Probs can do archives as 2 or more files
1. Archive for data that are backed up
2. Additional archives as needed for new data
3. Metadata with pointers to the correct archival for the metadata to file mapping

This leads to the open question (for other backup systems) of how to handle deletion and over time archives becoming out of date

Also leads to open questions on how chunked files stuff will work for other backups mediums (possibly even the worm one)

So probs can do something like
Data archive
Metadata archive
And then metadata can point to the companion and other data archives for the content as needed

Each data archive and metadata archive get its own key and stuff like that

Asym crypto for encrypting each data key for each archive or so


Then later on for any other data flow like small files that changes lots. Just make new archive every time?
Rozen 


Maybe one way to simplify it for myself.

Start with per archive snapshot and have each snapshot be “self contained” archive as one or several split files 


Once that snapshot and restore archive flow is working


Extend it to have cross snapshot references, ie each snapshot should be its own thing, later version can do partial and refer to other snapshots






Should figure out backup options
1. worm - data is immutable, ie photo archive, metadata may change (name location, permission, etc…. But the raw content stays same)
2. Fresh snapshot each time - for data that is small or changes lots so no point in trying to be fancy, just do a new snapshot every time , could have intelligence on if anything change locally do a snapshot otherwise skip and upload a index that refers to the older ones?
3. Unknown - not sure if we need incremental or other types because that tend to be complicated…. How do we want to handle this.

Let’s focus on the worm and then fresh snapshot cases first then extend software to support alternative format of archiving 



Archive header/identifier
Block[s]
Archive footer

Blocks
- type of block: file, index, etc…
- Block hash (pre processed)
- Length of block
- Optional cbor header
- Header hash
- Block data itself 
- Whole hash 

Can have ie a file block with file start then another block that has same hash and is file continue, then they end with a file end record which record location of all off the same file blocks

Then index block
Contains pointers to all block footers maybe or just pointer to all of each block grouped together

Then footer has pointer to index block for seekable 


The main bits is we need a way to connect all of the blocks where it’s like
FHDR, FCO[N]T and FEND

Or could be like

Hdr-> some metadata and linking id with optional header additional data via cbor in body of hdr

Then data with id and tally for snitching data blocks together, then a foot for footer with list of header to data block and footer for seek ability 




Aws streaming archive.

Need to have intelligent system that can retain parts that has been uploaded and resume from most recent checkpoint in case of system crash and be able to find all parts and resume uploading
Rozen

Packfile
1. 1gb or larger per pack file is the goal. Partial backup may cause a packfile
   to be smaller, need to handle this case at some point in time
2. Anyway if a new file is 1gb or larger, send it on up as it’s own packfile
3. If file is less than that, see how much room is left in archive(?) and stuff
   the file in there, if we end up a bit over that’s fine.
4. Do we want to check if it will fit in left over space or just shove it in
   and be done? I could see the merit since compression may play a factor.
5. Could probs do more fancy analysis, if media file it’s unlikely to compress,
   so send it on up, if it’s text or more likely to compress, take a chance and
   stuff it in the current archive?
6. Could just put the cap at how much “overage wr are ok with” Ie 100mb
7. But that would then imply/end up with second archive files smaller than the
   1gb goal we are after.
8. Is it better to be all roughly 1gb or are we ok with occasional 2gb archives
   in the worst case?
9. Considering how we already are ok with silly big archives in single file
   cases, it might merit just stuffing it in and have archive vary from minimum
   1gb or more
10. Main exception would be the final archive of a backup. Those may be way
    smaller.
11. Could hold it in an arena on s3 and once there’s enough of those smaller
    packfile run a compact job to compact them into a bigger packfile to put
    into glacier



1. Improve path (Ie do tree in database)
2. State machine in more location such as the builders to encourage and enforce
   correct pack, map and index file format 




I think this would be better suited to r/learnrust — certainly awesome that you
are learning the language! But I would caution against touching encryption
projects as a beginner, it is way too easy to get things totally wrong.

For one, you are not using a stream cipher. This means the entirety of the
source gets loaded into memory. Totally fine for a simple text file, but will
cause problems if you have to deal with decently large files.

You’re hashing the password 100,000 times to generate a key, but you’re just
chaining together sha2 hashes. This doesn’t really offer anything useful from a
cryptographic security standpoint. The idea of “hashing multiple times” is to
combine it with an intentionally slow, cryptographically secure hashing
function, so that a threat actor has to commit to a time cost if they want to
try and crack the password. For this you might want to check out something like
 argon2 . There’s also  scrypt ,  bcrypt , among others.

You may also want to check out  chacha20poly1305  for an AEAD cipher to use
once you generate your key. The docs have a pretty decent set of examples for
usage.

On getting the password from the user, you can check out the  rpassword  crate.
Right now your users have to enter a password in the clear on the terminal,
which always feels icky.

You may also want to look into handling passwords with some kind of
secure string implementation, or at least let the  zeroize  crate handle
zeroing out the memory.

I am by no means an application security expert, so this really is just
kinda scratching the surface on the encryption rabbit hole.

To nitpick a bit I guess, while functional this is a bit odd to read:


if { args.encrypt } == { args.decrypt }


You’re already using  clap , check the documentation on how to make
arguments required and mutually exclusive (take a look at ArgGroups
 enum  options, as recommended by u/SpudnikV).

Edit: removed incorrect info Edit 2: changed  clap  docs recommendation
Backup

Hash collision should never happen if it does then append a -1, -2 whatever to the object

1. Find candidates for backup
2. Process each (Ie with hash or other caches) for eliminating files already stored
3. Possibly at a later time do delta encoding and etc to save space for file changes
4. Compress the data
5. Encrypt the data
6. Store it into the backend

The authority on how fast to process things should be limited either by how
much cpu is needed for compression and encryption steps (mainly compression)
*or* back store speed at uploading/storage

Thus the backing store should regulate how fast the data is being read off
disk. And if it’s not then it should go as fast as it can because compression
is going to limit it’s top speed anyway.

Anyway. So once we have candidates and assuming the disks are extremely fast at
seeks (ssds) (will need to benchmark on Hdd) we can probs spin off a thread for
each file (to cpu limit or so) to crunch on each file and then upload in
parallel. Assuming network isn’t the limitor

