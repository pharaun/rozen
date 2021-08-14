Documentation of desired features.

Storage Target
	1. AWS S3 Buckets
		* Standard, Archive, Deep Archive
		* Can't run code on remote end
			- Could launch EC2 to handle this
	2. Filesystem
		* Initial testing?
		* If storing file as it is would need extend attr to store uid/gid for files
		* Otherwise if metadata is bundled with the file then it doesn't matter
	3. SSH FTP?
		* If support filesystem target

Storage Feature
	1. Encryption
		* Unclear what is best option here?
			- Symmerical Cryptography
				* Any merit of this?
				* I mean under the hood it will be Symmerical cryptography with asymmertric keys
			- Asymmetric Cryptography
				* Can allow the backup access to the public key
				* Will allow it to be able to generate a backup but not recovery/etc
		* Key distribution
			- Single master key
				* Whole repo
				* Per machine
				* Per backup
			- Single public key for all machines
			- Public key per machine & Single private?
			- Public key per machine & Multiple private key?
		* Signing the data
			- Detect alteration upon restoration
			- Probs covered by crypto hashes on things
		* Security
			- Threat model?
	2. Compression
		* Packed compression
			- Where everything is passed through the compression routine
			- More efficient compression
		* Unpacked compression
			- Where only the data is compressed one by one
			- Better for corruption and error recovery
			- Less efficient compression (Shouldn't matter past a certain size?)
		* Compression of already compressed artifacts
			- Do we want it to try to compress everything to get as much compression
			- Do we want to focus more on speed?
		* At what point is it worth to just eat the space loss cos of deep archive pricing?
	3. Deduplication
		* None
			- Stored as it is for each backup
		* Incremental File (Kinda per file deduplication)
			- Store whole file change incrementally
			- Requires the last whole + all incremental to date
				* Can do whole once a month
				* Weekly incremental against the last monthly whole
				* Daily incremental against the last weekly incremental
			- Delta to last whole or last incremental backup
		* Incremental File Delta
			- Store the delta of the file change incrementally
		* Block deduplication
			- Chunk each incoming file/backup into blocks
			- Store only the changed and different blocks
		* Delta Block deduplication?
			- Chunk each incoming file/backup into blocks
			- Delta diff it against near blocks
			- If sufficiently different that a delta isn't a win, store whole
		* Tiers of
			* Deduplication in term of per backup
			* Deduplication in term of all backup for a single machine
			* Deduplication in term of all backup for all machines
		* At what point is it worth to just eat the space loss cos of deep archive pricing?
	4. Partity
		* Reed-Solomon ECC
			- Good for recovering from subset of errors
			- Do we need it for S3 target?
			- What level of ECC do we want, per file, per archive per w/e
	5. Data integrity
		* Cryptographic hash on the backup metadata
		* Cryptographic hash on the backup data itself
	6. Concurrency
		* Multiple machine backup
		* How do we handle it, have a separate repo for each machine?

Filesystem features
	1. Sparse file
	2. Posix ACL
	3. File timestamps (create/modifed/etc)
	4. Extended Attributes
		* MacOS forks
		* Extended Unix ACLS (selinux)

File Finder
	1. Crawl the filesystem
		* Exclude Directory
		* Exclude File
		* Regex?
		* Global ignore/exclude list (ie *.swp, *.pyc)
	2. Metadata
		* Store metadata with file?
		* Store metadata change with empty file for metadata only change?
		* File move/renames?
			- How hard to catch/handle this?
			- Less need if its a block deduplication system
			- Needed more for per file deduplication/whole backups
	3. File Changed
		* Watchman (fb project to monitor file changes)
		* FSEvent (OSX api to monitor FS changes)

Backup features
	1. How much all in one system?
	2. Bother with OS/System backup or only personal data and /home dirs for eg
		* Priorization is user/personal data, the OS/machine can be rebuilt
	3. Tiers of backup?
		* WORM - Photography raw files?
	4. System impact/Performance
		* Resume backup interrupted by sleep?
		* Resume backup when program crashes?
	5. Style of backup
		* Continious (ie inotify/etc) and backup modification
		* Snapshots. (Daily, Weekly, Etc)
		* How to handle content changing from under
			- Inotify to monitor?
			- Retry?
	6. Multithreading
		* Reading from FS?
			- NVME/SSD are pretty fast with multiple reading threads
		* Compressing?
			- Heard its usually the slow part
		* Encryption?
		* Uploading to S3/SSH
			- Uncertain, dependent on upload + Link quality
	7. Pricing
		* Would be nice to have it print out the cost of each backup
		* When performing cleanup show how much it would save
		* Show the cost of IE. metadata vs actual data or so
	8. Restoring
		* Restore invidual files within a backup?
		* Require whole backup to be restored?
		* Provide a FUSE layer (for fetching invidual file?)
	9. Alternative approaches?
		* Always sync latest
		* Deduplication/delta/etc is for the previous backups to provide a history cheaper
		* Compare pricing
			- Spinning up an EC2 to do work on you behalf to the S3 repo
			- Structuring the S3 repo so that you can don't need additional work
			- Streaming the data back to client-side to reprocess ($0.09/GB exgress price)
		* Consider restoration speed
			- Will have to restore from Deep Archive -> S3 then fetch data so balance
				* Number of restores/time taken to do them
		* Store Metadata/other data into S3
			- DynamoDB an option?

S3 Bucket Validation
	1. Ensure that the bucket has the right policy
		* Currently Private only (no public sharing)
	2. Backup Mode
		* Can only append/write to a bucket, no modification or overwrite
		* Can (?) read from the bucket
	3. Admin Mode
		* Can modify objects in bucket?
			- Unclear if the data scheme will need to be able to rewrite
			- Would need some sort of compacting/purging/etc

Repo Validation
	1. Ensure that the repo is in a good and consistent state

Data Recovery
	1. Should be able to reconstruct the backup if the 'caches' are missing
	2. Catalogue/Indexes/Metadata are useful for speeding up backups
	3. Should if all else fail be able to at least get the data content itself

Scalability
	1. Mostly aiming for gigabytes/terabytes backup input
	2. Few machines not hundreds/thousands of machines
		* Do we want to even share machines in one repo?
		* Could always do multiple repo, one per machine
