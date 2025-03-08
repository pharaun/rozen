# Layers in the backup system

Rozen

Break up the incoming stream of files into “large and small objects”

Send large object (over X mb) to its own pack file and if there’s still room
take more small objects as needed otherwise send it on up.


Might be worth just separating the large object in its own zone and dealing
with it independently (Ie hundreds+ of megs for input files) (main catch is
compression but…)

Everything else under the limit goes to normal pack files to be packed ip.


Main issue is how to not have pack files sit around forever?

Seems like some form of chunking is needed. Unclear


I guess it just feels like all solution has complications. And there’s no easy
solution. We do want to be able to pack up small files for easy retrieval but.
We don’t want to have a ton of big file being cut up into chunks…. That becomes
error prone.

https://reddit.com/r/rust/comments/sx7nu7/lib_request_bufreading_a_pushbased_stream_of_bytes/

Look at something that track the in bytes and the out bytes to track the size
and compression ratio and then over time refine some sort of algorithm that try
to identify quickly what may and may not be super compeesssble data and average
ratio of various thin


Should then help with packing it up in pack files better

Could just have two queue. One for an ongoing pack file construction and for
files exceeding some threshold of then get sent to the large file queue to be
packed on its own




Consider early abort if file is under a certain size.

Also consider just reading file in memory below a certain size and test
compression directly before packing it. Otherwise past a certain threshold go
ahead and stream?

We already have good streaming support so continue but just Ie for certain size
just read it all into a buffer and encode it into the pack file directly rather
than streaming


Look at making more layers

Have a content access layer (cas) which deals with mapping hashes to data
streams and have various types of steam to help inform it how to store things
otherwise the above systems just work with hashes and streams

Then have backend that talks to disks or to s3 or whatever under cas


Normal backup stuff is a layer sbove the cas (compression and encryption)


Backend -> cas -> encryption/key management -> compression -> backup system


Other alternative is to just go all in on chunking and set something like
5-20 meg chunks and chunk anything larger than that and pack it up into
pack files and have everything go through the chunk flow of

1 chunk for majority of data then for the rarer data bigger than X size
chunk them in fixed chunks and handle it specifically



Look at what the minimum s3 multiparty upload. And handle chunk of that
size or less.

Then for file go ahead and compress and encrypt into a 5mb buffer and if
it’s not done inspect the file total to buffer and that should help us
develop an idea of the compression ratio.


Anyway can probs just handle everything below say 5MB as a single chunk and
send it in out to a pack file. Then for anything with more than 5mb stuff
it into a standalone (?) pack file and send it on up. It’s basically same
as normal pack file just degenerate case of just 1 file in it. So the rest
of the pack file index and layers would remaining working as usual.

The alternative is to just chop up all files greater than 5MB into chunks
and stuff them into pack files as hash-part1….99 or whatever for a simple
schema

For single thread code do 2 pack file at a time. A current open one and a
degenerate one. Basically if you hit a chunk too big to be put in a normal
pack file suspend it and pack it up and send it on out via degenerate pack
file then resume normal processing
