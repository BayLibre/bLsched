# bLsched

## Introduction:

bLsched is a user space daemon that is used to increase performance
on big/LITTLE systems by moving CPU instensive tasks to the big CPU cluster.
This is done by reading the load average for each task regularly, and if
the load average exceeds a certain threshold, the task is moved to the big
CPU set.

## Usage:

Usage: `./bLsched [-vbtinah]`
* `-v` Increase verbosity by adding one or more -v's in the arguments
* `-b` Add big CPU by cpu number, ex: ./bLsched -b 0 -b 1 adding CPU 0 and 1 to the big CPU set.
* `-t` Load threshold in % for moving to big cpu (default 90), if there is enough capacity on big CPUs
* `-i` Interval in ms for monitoring load avg. (default 1000)
* `-n` New pid boost. When enabled, new tasks are always put on the big CPU set.
* `-a` Existing tasks when starting bLsched, are added to the task list
* `-l` LITTLE cpuset default: Tasks not bound to the big CPU set, will run on the LTTLE CPUs instead of all CPUs.
* `-h` help

## Config:

* The linux kernel needs to be built with `CONFIG_SCHED_DEBUG`, so that the scheduler provides debug info in `/proc/<PID>/sched` procfs entry:

```
Kernel hacking  --->
   [*] Collect scheduler debugging info
```

* In order to detect taks creation, the linux kernel needs to be built with `CONFIG_PROC_EVENTS` enabled:

```
Device Drivers  --->
   {*} Connector - unified userspace <-> kernelspace linker  --->
      [*]   Report process events to userspace
```
