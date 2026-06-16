$ find . -type f -print0 | xargs -0 ls -l | awk '{ n=int(log($5)/log(2)); if (n<10) { n=10; } size[n]++ } END { for (i in size) printf("%d %d\n", 2^i, size[i]) }' | sort -n | awk 'function human(x) { x[1]/=1024; if (x[1]>=1024) { x[2]++; human(x) } } { a[1]=$1; a[2]=0; human(a); printf("%3d%s: %6d\n", a[1],substr("kMGTEPYZ",a[2]+1,1),$2) }'

  1k: 238167
  2k:  76675
  4k:  69124
  8k:  57270
 16k:  59650
 32k:  54940
 64k:  45543
128k:  40156
256k:  34583
512k:  21554
  1M:  15838
  2M:  21581
  4M:   9376
  8M:   5854
 16M:  14858
 32M:    731
 64M:    435
128M:   2528
256M:   2161
512M:    928
  1G:    410
  2G:    127
  4G:     58
  8G:     22
 16G:      6
 32G:      4
 64G:      2
128G:      3

CONCLUSION: majority of data is in the tens of MB and under - packfiles are recommended
