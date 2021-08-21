Backup

For file system driver could ponder a sqlite db for a single file backup, for experiments at least initially till on disk format stabilizes 

Whatever format is used should be glacier aware of the costs and retrieval time.

Will want to figure out how to structure things so that data can be stored as much together as is possible and in as few restore from glacier as possible.

Should still be able to rebuild the entire metadata layer on top from just the raw block data in glacier but that’s only for the worst case. For normal cases the metadata is stored in s3 for more near line storage.


Will need to understand what the workflow I want and go from there for designing the backup.

1. Should be able to restore a whole snapshot
2. Should be able to say “show me all snapshot that contains these files”
3. Should be able to retrieve a file from a snapshot
4. If can do that ^ could provide some form of fuse disk image layer for reading data (metadata for eg)
5. Would need to have ways to Ie clean up old backup and old data in an glacier cost aware manner.
6. If worst come to worst and need a whole archive rebuild can we spin up a ec2 machine to spare ourself the retrieval bandwidth?
7. Should be able to inform the user the cost of various operations like “fetch this data will take x time and cost $y”


Should have a way to validate the backup and a way to validate what is on disk (Ie diff the disk content to what is on backup)

Should be able to set a flag that says these files should never change. Backup can then treat them in a different way. Ie upon backup if it detects changes of these file emit an warning

Should have good flexible filtering Ie filtering out .gitignore for example (in some cases possibly. Other should back it all up…)


——

Cost estimator. I want a way to estimate cost of various options. So that the user knows how much each option will cost.

For compact and gc we can probs do it in a couple of stages since the data pack is stored in glacier. Can probs mark each data pack as having more dead chunks over time and once a data pack is empty can possibly purge it after a certain time (cuz glacier)

Could indicate how much of the cost is ate up by dead chunks and over time if it’s sufficiently high prompt the user to do a gc/compacting pass

This will then pull things from glacier, compact it and purge the old entities. The main key is that it happens in stages ie “pull the data, compact it and store new data back into glacier” then in a later/separate run do the discard.

This would theorically allow more of the system to be in append or write once mode and then rarely can launch a fargate container for discarding old data with a separate key or something.

Need to make sure we break up the system in at least 2 separate type. One that can add new backup and some stuff. The other that can perform admin purge stuff of old data.

This should all show the cost of various options so the user can decide when it’s worth it or not.

The normal mode should be append only. Such as “append a new compact object” then somewhere mark the old one to go away or allow the system to analyze things and go ok “this new one replaces these old ones and these old ones don’t have backups anymore, purge”

Need to make sure hopefully of everything goes bad can read back the data blocks to rebuild all layers above as needed but that would be expensive 


——

Bsdiff explosive memory usage
Xdelta good but need source and destination
Rdiff less good but only need source and sig (can be cached)


——

Priority:
1. Append only storage
2. Can delete/cleanup with a separate admin key
3. Know the cost of each backup and various operation
4. Should be able to recover from just the bare backup stripes/archives
5. Deep archive s3 enabled for the data bands.
6. Should be able to restore a single file or a subset of backup without fetching the entire collection
7. Should be compressed and encrypted
8. If have to can use a ec2/fargate instance as a control plane for disallowing overwrite (either via transmitting data via or via it rolling back anything but oldest version automatically)
9. Client can only send down new data
10. Needs admin for removing backups or pruning or any sort of repository rearrangements
11. Should be able to use some form of ingestion encryption such as public key for ingestion but have no way to recover without a password or private key to prevent exploited clients from recovering data 
12. Should have a way to do some form of basic incremental or not backups. Such as sending up an backup archive that contains the ref to all data packs that contains the backup yet not inflate on space usage
13. Not sure if delta encoding or deduplication on blocks or whatever is the right fit, need to evaluate the above goals with complexity and speed of restore since it’s being pulled out of glacier
14. Should be price aware/sensitive as in it let’s the user know the cost of various operations and the user can decide the speed and trade offs 

——

Should have concept of backup engines since we want to store different set of data in different ways.

1. A worm one which writes the backup once and then warn if the source data got deleted or changed so the user can restore from backup
2. A delta/dedup backup for home directory that has small files and files that are prone to changing lots
3. Some sort of long term delta for virtual machines (low priority)
4. Sync (take the data locally as authoritative and sync it to s3)

