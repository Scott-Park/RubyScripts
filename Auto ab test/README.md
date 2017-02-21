# Ruby Auto ab test script
This script support repeat ab test and calculate average.
<br>Basically use ab(apache benchmarking) binary

## Usage>

```
[root@localhost ab]# ruby ab_auto.rb
Usage: ruby ab_auto.rb [options]
    -r, --req REQUEST                Number of requests to perform for the benchmarking session.
    -c, --con CONCURRENCY            Number of multiple requests to perform at a time.
    -u, --url URL                    URI for test.
    -n, --ntimes NTIMES              Number of repeat test.
    -h, --help                       Help of usage.

```

## Example>
```
[root@localhost ab]# ruby ab_auto.rb -r 100 -c 30 -u http://userhost/ -n 10
Begining of test...
Thread 9 test_time: 0.359
Thread 9 mean_time: 107.789
Thread 1 test_time: 0.363
Thread 1 mean_time: 108.927
Thread 8 test_time: 0.354
Thread 8 mean_time: 106.074
Thread 4 test_time: 0.391
Thread 4 mean_time: 117.281
Thread 6 test_time: 0.395
Thread 6 mean_time: 118.603
Thread 5 test_time: 0.414
Thread 5 mean_time: 124.238
Thread 7 test_time: 0.363
Thread 7 mean_time: 108.941
Thread 0 test_time: 0.402
Thread 0 mean_time: 120.562
Thread 2 test_time: 0.395
Thread 2 mean_time: 118.644
Thread 3 test_time: 0.438
Thread 3 mean_time: 131.504
-===[ average of 10 times test ]===-
average of time taken: 0.3874000000000001 seconds
average of time per request: 116.25630000000001 ms(milliseconds)

```

## Dependency
For using this script, you should be require ab binary on your testing machine and target machine must be running the Apache server.
<br>My ruby version is **ruby 2.3.1p112**

**[Ubuntu]**

```
# sudo apt-get update
# sudo apt-get install apache2-utils
```

**[CentOS]**

```
# yum update
# yum install httpd-tools
```
