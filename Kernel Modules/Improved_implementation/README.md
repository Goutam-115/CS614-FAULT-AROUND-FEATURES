We inserted the code mentioned in the C source file inside the mm/memory.c file just preceding the do_anonymous_page() function and compiled the kernel.
Additionally, to incorporate our handler into the do_anonymous_page function, we included supplementary lines to trigger our handler whenever certain debugfs variables are configured.
The specific lines are lines 54-57 in the modified_do_anonymous_page.c file attached.

After the kernel is compiled succesfully and rebooted, we will find 2 variables in the /sys/kernel/debug directory :
1) nr_prefault_page
2) tracked_pid
The nr_prefault_page can be used to set the number of pages that you need to prefault at once just like fault_around_bytes. By default set to 4096 bytes or 1 page as is the case without prefaulting.
Usage :
# Say I need to prefault next 16 pages, then use the command :
$echo 65536 | sudo tee /sys/kernel/debug/nr_prefault_page 
And tracked_pid is the pid of the process that you want to apply prefaulting for.