# Todo list/design question list.

Key/value store with specific constraints/requirement for the data store layer
- This basically is a better put together CAS system
- It handles packing up smaller values into larger log-strips
- It handles splitting up the 'type' of data (ie long term storage, and metadata, and index) type of storage
- It has some basic key (ie all item must have a blake3 content hash as the key),
    * There may be optional other key types to allow for other operations.
    * Would need to figure out how to handle this for ie index/other important bits, but could probs build it on top
    of the main blake3-key -> content database part
- Whole thing is structured in a grouped append only log format to allow for "ACID" and durtibility
    * Allows resuming a failed backup
    * Allows referring to other data
    * Allows building packfiles via appending for smaller data to allow for efficient s3 storage
- Prune/compaction can be done with a different process
    * Probs will have complications with dealing with data/packfiles but that can be deferred to storage manager

Look and research how K/V databases work and take inspiration from them for building the object key value storage system.
- Maye one storage simplification. Have each data chunk be of a max size,
    - large file will have a metadata chunk that lists all of the chunk that is in it
    - smaller files will be its own chunk
- This turns everything including large files into a packfile problem then we can use same solution for them all
- Can optimize for small files -> direct refer the data chunk, large file -> large file chunk -> its data chunk

File structure:
    [stripe header]
        [data block]
    [file block]
            [large data block 1]
            [large data block 2]
            [large data block 3]
        [large-blob-ptr]
    [file block]
        [data block]
    [metadata block]
    [hash-\>offset index]
    [end-of-strip -> hash index]

Then we can add additional types over time, this would be for like flat file
format, for something like s3 it would be more like

data/
    stripe
        [stripe header]
        [data block]
        [large data block 1]
        [large data block 2]
        [large data block 3]
        [hash-\>offset index]
        [end-of-strip -> hash index]
    metadata
        [stripe header]
        [file block]
            [large-blob-ptr]
        [file block]
            [data block]
        [metadata block]
        [hash-\>offset index]
        [end-of-strip -> hash index]

This would then allow us to send the raw files to cold-store, where the metadata stay in hot store
then we would also need to look at how key/value database work and employ that for the rest of the data stuff

Can later on look at 'packed data block' or something if we need to for effiency reasons, but for now don't

Naming:
    basin - collection of strata
    strata - stripe (linear collection of grain)
    clasts - (Linear collection of grain)
    grain - record (key/data/etc)

grain format
    [strata header]
        [Version]
        [key material]
    [strata header]
        [grain-start]
            [XxHash32]
            [Length] - length of the grain not including the hash
            [Key]
                - [content-blake3 hash]
                    [Single-grain sized record]
                - [content-blake3 + '-' + part-number -> blake3 hash]
                    [Multi-grain sized record]
            [Data]
                [Encrypted and compressed blobs of data]
        [grain-end]
    [strata footer]
        [pointer to grain that contains the grain-index]

metadata format - data (within the [Data] segment of a grain)
    [grain-index]
        [key] -> [offset in the strata to the grain]
        ....

    [clasts]
        [content-blake3 hash]
            [content-blake3 + '-' + part-number -> blake3 hash]
            ...

    [snapshot]
        [directory metadata]
        [file metadata]
        [snapshot metadata]


I give up right now here's a list of bookmarks:
 https://docs.rs/persy/1.6.0/persy/
 https://github.com/khonsulabs/nebari?tab=readme-ov-file
 https://github.com/surrealdb/surrealkv
 https://slatedb.io/docs/introduction/
 https://docs.rs/object_store/latest/object_store/
 https://github.com/fjall-rs/fjall
 https://www.tunglevo.com/note/build-a-blazingly-fast-key-value-store-with-rust/
 https://bonsaidb.io/blog/optimizing-bonsaidb-p2/
 https://github.com/khonsulabs/sediment/tree/main/src
