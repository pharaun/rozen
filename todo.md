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
    grain - record (key/data/etc) (key + part)

Strata format
    [Strata Header]
        [Strata Magic]
        [Version] - 8 bit
        [Basin ID] - 8 bit to know which basin this Strata belongs to
        [Strata ID] - 16/24bit Strata Id (Figure out how big the smallest grain is and how big the file would be)
        [Header Options]
            [Encryption Key material]
            [Compression material]
    [Grain]
        [Grain ID] - 32bit Grain Id
        [Length] - length of the grain
        [XxHash32]
        [Key]
            - [content-blake3 hash]
            - [part]
                - Integer
                - 0 for first part -> some 8bit/16/32bit limit of parts
        [Data]
            [Encrypted and compressed blobs of data]
    [Strata Footer]
        [blake3 hash of the whole Strata file]
        [Signature of the file for integrity?]


Index Format - TBD
    [Sorted list of Basin]
        [Basin-ID]
        [Sorted list of Strata]
            [Strata-ID]
            [Sorted key+part table]
                [Key][Part] -> [Grain-ID][Offset to Grain + Length]
