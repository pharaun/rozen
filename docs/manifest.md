1. One client per repo
	- Can be one computer
	- Can be one NAS
		* Syncthing/unison/rsync.... to synchronize from all other device to the NAS
		* Later version can enable intelligent streaming of data from the client to the
			central daemon (with cache directory on the NAS(
		* Recommended structure is something like:
			machines/
				machine1/
					<...> machine 1 data in invividal files
				machine2/
					<...> machine 2 data in invividal files
			shared/
				<...> data shared between all machines
		* Directory structure does not have to be honored or whatever since in version 1
			the NAS/one client will be streaming all of the data/backup from the machine itself
			thus duplicate files on the NAS will naturally get deduplicated (i believe)

2. All devices sync to the central NAS
	- At a later date it can become an actual daemon where each client streams its data to
	- At a later date it may become possible for each client to compress+encrypt+etc the data
		before streaming it to the central daemon
	- For now all machines sync/send their backup data to the central machine for backup

3. Central daemon at a later version can be improved
	- Allowing append only backups
	- Allowing various methods of control (where clients *push* the backup to the daemon)
	- Allow one special account or better yet a separate tool/key to be able to do destructive
			operation such as deleting old backup and various things
	- Unclear if each client could on its own connet to the cloud backup to restore (?) may be
		better in initial version to only allow the NAS to restore then the clients can retrieve

4. Configuration
	- Should store all essential information in the cloud for ease of restore/setting it back up
	- Have one central configuration (in version 1, later one each machine could have its own)
	- This config will mark which directory/file gets what treatment such as
		* worm - write once backup for data that are supposed to never change
		* normal - for home directory or data that changes lots
