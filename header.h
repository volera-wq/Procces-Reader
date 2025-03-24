#ifndef _header_h_
#define _header_h_
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>




typedef struct _PROC
{
    int pid;
    char* name;
    char* cmd;
}proc;


typedef struct _STATISTIC
{
    int min;
    double avg;
    int max;
}stat;


typedef struct _INFORMATIONS
{
    char* first_read;
    char* last_read;
    char* umask;
    char* last_state;
    int number_of_scans;
    int file_description_size;
    int peak_virtual_memory_size;
    int locked_memory_size;
    int pinned_memory_size;
    int peak_resident_set_size;
    stat virtual_memory_size;
    stat resident_set_size;
    stat resident_anonymous_memory_size;
    stat resident_file_mapping_size;
    stat resident_shared_meory_size;
    stat data_segment_size;
    stat stack_segment_size;
    stat text_segment_size;
    stat shared_library_code_size;
    stat page_table_entries_size;
    stat swaped_out_virtual_memory_size;
    stat hugetlb_memory_portions;
    stat number_of_threads_in_process;
}info;


typedef struct _TOTALS
{
    proc prc;
    info inf;
}totals;


void *xmalloc(int);
void wait(int);
void PrintActuaProcesses(totals*, int);
void Scan(totals*, proc*, int, int);
void WriteProcess(proc, int);
int NumberOfLinesInFile(char*);
size_t find(char*, char*);
_Bool AlreadyExists(int, int, char*, totals*);
_Bool OnlyPidExists(int, int, totals*);
_Bool OnlyNameExists(int, char*, totals*);
char* substr(size_t, size_t, char*);
char* Beautify(char*);
proc* ReadGoodProcesses(char*);
totals* ReadActualProcesses(int*);
totals* RepeatRead(int*, totals*);
totals* ComposeNew(totals*, totals*);
stat RefreshStatistics(stat, int, int);

#endif