This module creates two sysfs groups: "cs614hook" and "map_populate_hook". The "cs614hook" group comprises two sysfs variables: "tracked_pid" and "tracked_faults". The "tracked_pid" variable is designated for setting the process ID to be monitored for faults, while "tracked_faults" is utilized to display the various types of faults experienced by that process.

The second group, "map_populate_hook", contains a single variable named "populate_flag". When set to 1, this flag applies the MAP_POPULATE attribute to every mmap call made for the tracked process.

Moreover, the module implements two kprobe hooks: one on "do_mmap" and another on "handle_mm_fault". The "do_mmap" hook configures the "map_populate" flag for each memory allocation pertaining to the currently tracked process. On the other hand, the "handle_mm_fault" hook manages the tracking of page faults.

To generate the complete logfile please remove the module 
Along with this it prints every fault's address, its type and the time at which it was obtained into a logfile which after running a python script converts to a csv file which is readable.