The backup system is using a content hash of each file archived for the key for storage in S3 or on disk filesystem. This leads to 2 main approaches to hashing/handling the initial content hash generation.

Approach 1:
    1. Hash the file in 1 pass before hand to get the content-key
    2. Stream the file to a ~10MiB buffer:
        * Rehash (to ensure file did not change)
            - For S3 upload, hash the md5
        * Compress (Zstd)
        * Encrypt (TBD)
    3. Once the file is all read or the ~10MiB buffer is full, send it via multi-part to S3
    4. Before finalizing upload, if new hash & prior hash does not match, abort upload and try again

    Pros:
        * No write to disk
        * No larger buffer (not strictly neccassarly)
            - Can optimize for files < Buffer by reading it all in then processing it
                * This could double the buffer usage (10MiB file + xMiB buffer)
        * **Maybe** More robust tamper detection (file change during read)
            - mtime + other detection helps
        * Can hash the file to identify if backup already contain file (in strict hashing mode)
            - Saves cpu time for Compress & Encryption
            - Compression is way more expensive cpu-wise

    Cons:
        * Double read from disk
        * Double hashing cpu time
        * May not strictly save a write to disk (since disk cache could cache the tempfile)
        * 100MiB read -> Hash 1, 100MiB read -> Hash 2 in worst case

    FS Snapshots:
        * Omit the second hash, which saves on compution time
        * Still has the "double read" in the worse case

Approach 2:
    1. Stream the file to a ~10-100MiB buffer:
        * Hash (for key)
        * Compress
        * Encrypt
    2. If file larger than the buffer
        * Create temporary file
        * Dump buffer
        * Write any further data to temporary file

    Pros:
        * Save 1 excess hashing (which can add up)
        * Best case 1 read - read < buffer capacity

    Con:
        * May end up writing to disk if temp file exceeds disk cache
        * 100MiB read -> upto 100MiB write, *then* upto 100MiB read in worst case.

    FS Snapshots:
        * Still need to buffer it to tempfile
