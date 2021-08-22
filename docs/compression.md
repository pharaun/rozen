Compression:
    tar  - 1.0G - 1s
    lz4  - 373M - 2m 34s
    lzo  - 349M - 3m 49s
    gz   - 304M - 1m 43s
    dar  - 294M - 1m 11s (Tar+bz2 replacement)
    bz2  - 287M - 58s
    dar  - 260M - 5m 59 (Tar+zstd replacement)
    zst  - 160M - 5m 6s (zstd)
    lz   - 160M - 6m 53s (lzip - lzma based)
    xz   - 153M - 7m 3s (lzma/xz)
    zst  - 136M - 5m 39s (zstd wlog=31,strat=9,clog=30,slog=30)
    lrz  - 136M - 33s (zpaq failed) (long dictionary lzma) (lrzip)
    zpaq - 135M - 9m 43s
    br   - 126M - 31m 15s (brotli)

Chunk Compression:
    tar            - 1.2G
    per file       - 332M
    per 10Mb chunk - 246M
    tar.zst        - 150M

Deduplication:
    Works:
        fpgaminer/preserve - 1.0G (Claims to compress with xz and stuff but?)
        restic/restic - 995M (No compression of blocks)
        andrewchambers/bupstash - 456M
        sourcefrog/conserve - 455M
        dpc/rdedup - 294M
        bup/bup - 294M
        asuran-rs/asuran - 261M (zstd,22)
        borgbackup/borg - 241M (zstd,22)

    Busted:
        zbackup/zbackup - (Complicated installation, no thanks for now)
        basak/ddar - (Python something couldn't get it setup, i think py2.7?)
        derekp7/snebu - (Client/server setup, kinda complicated to get going?)
        kopia/kopia - (Works but is unclear what it all backed up)

    TBD:
        duplicati/duplicati
        gilbertchen/duplicacy
