AWS Break Even price point

$ 0.09 - 1 GB - download
$ 0.0004 - 1,000 - get, other api calls

1290 bytes header

Should be able to do suffix range (from the end aka range=-10 for 10 bytes or so)
 1. Get index pointer (several bytes)
	a. optimization of just fetching last couple kilobytes (need analysis on reasonable defaults)
	b. would allow to do 2 get request (index + data)
 2. Get index (bytes - kilobytes)
 3. get data

Assumption - worst case cost is.
1. 3x gets
2. data cost = 3xheader + bytes + kilobytes + data (?)

Fetch case
1. 1x get
2. data cost = 1x header + data


TEST CASE?
	1. 10MB fetch
	2. 1,000 fetches
	3. 1,000 packfiles (100MB each)
	4. 10x 10MB each packfile - Index = 10 * 50 bytes => 500 bytes index

Just Fetch case:
	1. 1000 x 100MB => 100 GB
	2. 1000 get request
	3. 1000 x 1290 bytes header

	COST: $9 data + $0.0004 api + $0.00016 header data
	OH: 0.006% overhead

Index Fetch:
	1. 1,000 idx fetch - 4 bytes each -> 4000 bytes total
	2. 1,000 index fetch - 500 bytes each -> 500,000 bytes total
	3. 1,000 data fetch - 10MB each -> 10,000 MB total
	4. 3,000 x 1290 bytes headers -> 3,870,000 bytes

	COST: $0.9 data + $0.0012 api + $0.000348 header data + $0.04536 idx data
	OH: 5.212%

	SKIP-idx fetch
	COST: $0.9 data + $0.008 api + $0.0002322 header data + $0.04536 idx data
	OH: 5.14%


Conclusion:
	1. index + etc is fine for ranged get mostly at the megabytes level, under that it might become questionable
	2. might want to consider at some point if doing a restore it might be worth fetching whole pack file and extracting
		all relevant records out of the pack files one by one depending on how full a packfile is. this means bunch of
		download optimization code can be done. at the least want to cache the indexes to avoid re-fetching the index everytime
