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
    0. MANDATORY:
        * FS snapshot (apfs or zfs or btrfs)
    1. Encryption
        * Guard against plain text attacks
            - DAR padding the data?
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
        * Multiple keys?
            - One key for metadata + files
            - One key for chunks in an index
                * Allow decompression on untrusted ec2 machines for garbage collection
    2. Compression
        * Compression engine to use:
            - Zstd
        * Unpacked compression
            - One data chunk per compression block
            - Less efficient on small files
            - More resistant to corruption
            - Better indexability
        * Compression of already compressed artifacts
            - MAYBE: compression check with high speed Zstd
            - If no good, either continue or skip to encryption layer
    3. Deduplication
        * Per file deduplication
            - Store whole file and deduplicate based off this
        * Future Deduplication improvement
            - Incremental
                * rdiff/delta encoding to save space
                    - Bsdiff explosive memory usage
                    - Xdelta good but need source and destination
                    - Rdiff less good but only need source and sig (can be cached)
                * restore challenges (need all delta+original)
            - Block
                * Chunk each incoming file/backup into blocks
                * Store only the changed and different blocks
            - Block and Delta
                * Same as Block with addition of delta encoding for adjecent blocks
    4. Partity
        * S3
            - No partity (they do on our behalf)
        * Future improvement
            - Reed-Solomon ECC
                * Mainly for on disk recovery of physical media
                * See: par2
                * See: darrenldl/blockyarchive
    5. Data integrity
        * Cryptographic hash on metadata
        * Cryptographic hash on data
        * CRC/hash on all headers
    6. Concurrency
        * Multiple machine backup
            - Synchronize data to a central machine
            - Backup from the central machine
            - Outside scope
    7. External scripts?
        * Some way to invoke external script on backup start and stop

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
        * Flexible filtering such as filtering according to .gitignore files for eg
    2. Metadata
        * Store metadata with file?
        * Store metadata change with empty file for metadata only change?
        * File move/renames?
            - Solve via hashing on file content
            - Main challenge is for per-file delta/deduplication
            - Less need if its a block deduplication system
    3. File Changed
        * Monitor modification time for changes
        * Pre-hash file for the key generation for storage
            - Rehash on processing and if final result different, retry
        * Kernel FS monitor
            * Watchman (fb project)
            * FSEvent (OSX)

Backup features
    1. Don't bother with OS/System backup, only personal data (ie /home dirs)
    2. Tier of backups
        * WORM - photography raw files, these should never change
            - Probs can store two set of index, one for WORM, one for normal
            - Validation of local copy and restore from backup if local copy is corrupt
            - Issue warning if local data changes
        * Normal - homedir data
            - Changes often
    3. Error recovery
        * Resume backup when interrupted by sleep & crashes
    4. Style of backup
        * Continious
            - inotify/fsevent watchers...
        * Snapshots
            - Daily to Weekly
    5. Multithreading
        * Directory Walking
            - Fast on SSD
        * Compression
            - Likely to be slow part
        * Encryption
            - Usually faster than compression
        * Uploading
            - Dependant on uplink
            - Probs bottleneck
            - Can parallel to a certain point then it'll block all previous steps
    6. Pricing
        * Would be nice to have it print out the cost of each backup
        * When performing cleanup show how much it would save
        * Show the cost of IE. metadata vs actual data or so
        * Should be glacier aware and inform the user of implications here
            - Could restrict Glacier to WORM data
        * Let the user know the cost of various operations like fetching X data will
            take x time and $y
    7. Restoring
        * Easy to restore invidual files
            - Consult indexes and fetch the correct file block
        * Easy to restore whole backup
            - Consult indexes and parallel-fetch the file blocks
            - Winkle if additional processing like Delta/etc
    8. Scheduling of backup
        * Daily backup
            - If nothing change, upload an small index indicating to look at previous index?
        * Further back employ some prunning strategy?
            - Mostly dependent on index size
            - Mostly dependent on GC effiency
    9. Multiple machine backups
        * One client per repo
            - Can be one NAS
                * Syncthing/unison/rsync
            - Layout:
                machines/
                    machine1/
                        <...> machine 1 data
                    machineN/
                        <...> machine n data
                shared/
                    <...> shared common data
        * MAYBE: Central daemon
            - Enable each machine to compress/encrypt their own backup
            - Stream the backup through daemon into cloud
            - Daemon enforces append only backups
            - Secured backup machine with S3 keys, clients can be compromised and push
                bad data but they can't access s3
            - Restoration
                * Could use the daemon to restore a backup stream on the client behalf
    10. Configuration
        * Could store the config into the cloud service for ease of restore

S3 Bucket Validation
    1. Ensure that the bucket has the right policy
        * Currently Private only (no public sharing)
    2. Backup Mode
        * Can only append/write to a bucket, no modification or overwrite
            - Enforced via bucket versoning?
    3. Admin Mode
        * Prune via iterating through indexes and deleting old enough ones
        * Prune via deleting backup blocks not referred in indexes
        * Require decryption of indexes

Data Recovery
    1. If one block lost, that file is lost
    2. Should be able to restore most data with a loss of indexes
        - Main challenge is file names/duplicate file names....
        - Store multiple Index files?
    3. If all else fail should be able to gain access to the content itself
