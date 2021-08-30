Backup

Multiple tiers, for now 2:
1. Cold data
2. Warm data

Basically cold data are:
1. Data that goes into deep archive
2. Are long term storage and need high integrity protection (spinning rust)
3. Unlikely to want to restore *one* file in the collection
4. Maximum compression for storing as much data in cold store and keeping bandwidth cost down when retrieval of the archives
5. Balance between download speed, rentation time (when restored) and archive size so that we only need to reload a few big blocks at a time
6. Likely to be append only data.
7. If new data, put a note in the archive + warm storage index to skip the restoration of older data.
8. New data should be rare
9. Should generally warn if there are new changes since that means the local storage is degrading/bit rotting.
10. Likely to be raw photos, various other large media files
11. Need good work flow for restoring from glacier and monitoring restoring status and various aspects.

Basically warm data are:
1. Likely to be small rapidly changing data such as source code and so forth
2. Likely to want to honor gitignores so that it doesn’t backup binary artifacts that can be rebuilt from source code
3. Not sure yet on how common restoring one file or directory would be, but probs want to balance restore against compression efficacy 
4. Specifics to be further developed, for now focus on the cold data storage


Consider
1. Version based backup
2. Able to retain x versions. If things has not changed then it’s still one version
3. Tag the version with a time delta so you can know when each version and time delta it is but otherwise work in terms of versions 


For worm backup:
1. Have bands where a band is each backup that has data change/append
2. Store it all into s3 till backup is good then move into deep archive the backup band
3. Have a catalog at end of each file for content in each archive
4. Have a whole backup catalog in index on s3
5. If index corrupt, rebuild from individual archive catalog
6. If those corrupt scan whole archive to build an per archive catalog
7. Consider the idea of storing a short catalog file copy along with the archive with its built in catalogue (to make it glacier friendly?)



Primary box it is running on:
1. The nas
2. Other machines can send copies of their files to the nas
3. Open question if a two stage backup is the right call. Ie archiver to grab data off each machine and put it onto the nas for final upload into s3
4. The question then becomes how to support extended and other special data of each system on the nas
5. Another question is the. How to ingest the backup archives into the cloud. Ie we wouldnprobs want to do some form of deduplication and other steps to reprocess the data before upload to reduce the amount of copies and so on in the cloud
6. Maybe some form of syncthing or some other sync to send data from machines to the nas. Nas can then be resting location for data to go into the cloud
7. Might want to consider a few separate stages if possible that can be pipelined (ie the intake into archive then the cloud management and api portion)

Each machine can have a cache that delta and send incremental changes to the nas over smb or whatever synchronization.

The nas can then take the archive file and reprocess it for storage into cloud and take any other files on the nas and store it into the cloud.

An option is also to setup some form of sync from all machines to the nas then the nas surlp it up for cloud backup.



One approach could be a simple server for coordination and talking to the cloud service then each computer has its own client which then stream to the server for cloud coordination for example. Then if it’s ran on one client they are linked together in a binary or split with a small network stack in between
