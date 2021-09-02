Archiver Api:
    <prefix>/
        ROZEN.json
            {
                Version: 0
                // Todo: any repo-wide settings here
            }

        // HMAC hash? (256 bit -> 64 char hex)
            * Blake3?
            * Current edition 1 file = 1 hash, future may change that
            * Hash of file content?
                - Can't stream it would have to spool it locally to finish hash
                - If its a HMAC hash a change of the key will change the hash
                - Use asymmerical crypto w/ pub key to add to repo and password to decrypt
                    private key, i think this ends up doing symmerical crypto on the inner
                - Can prehash the content and compute a new hash as you are streaming to
                    identify if the file changed, if so abort upload and retry
        DATA/
            <00..FF>.roz
                {block header}
                    [u64 - "ROZE-DAT" Magic bits]
                    [u8 - Block version]
                        * 0...254 versions
                        * 255 Reserved for future expansion

                {encryption header}
                    []

                {compression header}
                    []

                // TODO: how to handle these metadata delta?
                {FS Metadata}
                    * Posix permissions
                    * File times (create/access/etc)

                // TODO: how to handle these metadata delta?
                {EA Metadata}
                    * extended attributes
                    * osx resource fork

                {DATA}

            // TBD: need some transactional log to write file names and other metadata here
                so that its possible to rebuild indexes if things goes bad?
            // TODO: is this desirable or good or should I instead depend on the index for this
                what is the recovery game for partal index loss and total index loss? For chunk
                loss we only lose that one file chunk
            // TODO: possible to do without this and instead make sure to write a new index for each
                backup run so there's multiple copies of each index for corruption purposes
            <00..FF>.roz-log/
                0000.roz-log
                9999.roz-log
                    {similiar headers as *.roz}
                    {data}
                        * Contains one file path per slice

        INDEX/
            <00..99>.idx
                {block header}
                    [u64 - "ROZE-IDX" Magic bits]
                    [u8 - Block version]
                        * 0...254 versions
                        * 255 Reserved for future expansion

                {encryption header}
                    []

                {compression header}
                    []

                {SQLite catalog}
                    * Contains the entire index of each backup run
                        including unaltered files
                    * Schema:
                        File path -> data/<00..FF>.roz blobs
                        Any effiency metadata such as rdelta sigs?
                            - allows efficient delta encoding of new data
                        Possibly metadata storage?
                            - How much space would this take, since its recreating this
                                on every backup in full
                        Special files
                            - hard links
                            - Sym links
                            - ...
