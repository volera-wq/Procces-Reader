#include "header.h"


void *xmalloc(int length)
{
    void *p = 0;
    p = malloc(length);

    if(!p)
    {
        fprintf(stderr, "Error: Can't allocate memory!");
        exit(EXIT_FAILURE);
    }

    return p;
}


void wait(int seconds)
{
    clock_t start_time = clock();
    while((clock() - start_time) / CLOCKS_PER_SEC < seconds);
}


int NumberOfLinesInFile(char* path)
{
    FILE* file = fopen(path, "r");
    int count = 0;
    char line[2048];
    if(!file)
    {
        fprintf(stderr, "Error: Could not open the file!");
        return -1;
    }

    while(fgets(line, sizeof(line), file)) count++;
    fclose(file);
    return count;
}


_Bool IsNumeric(char* c)
{
    while(*c != '\0')
    {
        if(*c < '0' || *c > '9')
            return 0;
        c++;
    }
    return 1;
}


size_t find(char* str, char* v)
{
    size_t pos = 0;
    while(*str != '\0')
    {
        if(*str == *v && *(str + 1) == *(v + 1) && *(str + 2) == *(v + 2)) return pos;
        pos++;
        str++;
    }
    return -1;
}


char* substr(size_t start, size_t len, char* str)
{
    if (start < 0 || len < 0 || start + len > strlen(str)) {
        return NULL;
    }
    char* substr = (char*)xmalloc((len + 1) * sizeof(char));
    strncpy(substr, str + start, len - 1);
    substr[len] = '\0';

    return substr;
}


char* Beautify(char* str)
{
    int i;
    if(strcmp(str, "nonvoluntary_ctxt_switches:") == 0);
        return "";
    for(i=0; i<strlen(str); i++)
    {
        if(str[i] == '\0')
        {
            str = substr(0, i, str);
            break;
        }
    }
    return str;
}


_Bool AlreadyExists(int num, int pid, char* name, totals* list)
{
    int i;
    for(i = 0; i<num; ++i)
    {
        if(pid == list[i].prc.pid && strcmp(name, list[i].prc.name) == 0)
            return 1;
    }
    return 0;
}


_Bool OnlyPidExists(int num, int pid, totals* list)
{
    int i;
    for(i = 0; i<num; ++i)
    {
        if(pid == list[i].prc.pid)
            return 1;
    }
    return 0;
}


_Bool OnlyNameExists(int num,  char* name, totals* list)
{
    int i;
    for(i = 0; i<num; ++i)
    {
        if(strcmp(name, list[i].prc.name) == 0)
            return 1;
    }
    return 0;
}


stat RefreshStatistics(stat s, int actual, int n)
{
    if(actual < s.min) s.min = actual;
    if(actual > s.max) s.max = actual;
    s.avg = (s.avg * (double)(n - 1) + (double)actual) / n;
    
    
    return s;
}


void WriteProcess(proc list, int firstCall)
{
    char* mode = firstCall ? "w" : "a";
    FILE* file = fopen("process_killed.txt", mode);
    fprintf(file, "<PID>%d<NAME>%s<CMD>%s<END>\n", list.pid, list.name, list.cmd);
    fclose(file);
}


void PrintActuaProcesses(totals* t, int number_of_processes)
{
    FILE* file = fopen("processes.txt", "w");
    int i;
    for(i = 0; i<number_of_processes; ++i)
    {
        
        fprintf(file, "<PID>%d<NAME>%s<CMD>%s<END>\n", t[i].prc.pid, t[i].prc.name, t[i].prc.cmd);
        fprintf(file, "<FIRST READ AT> %s\n<LAST READ AT> %s\n", t[i].inf.first_read, t[i].inf.last_read);
        fprintf(file, "<NUMBER OF SCANS> %d\n", t[i].inf.number_of_scans);
        fprintf(file, "<PROCESS UMASK> %s\n", t[i].inf.umask);
        fprintf(file, "<LAST PROCESS STATE> %s\n", t[i].inf.last_state);
        fprintf(file, "<FILE DESCRIPTION SIZE> %dKb\n", t[i].inf.file_description_size);
        fprintf(file, "<PEAK VIRTUAL MEMORY SIZE> %dKb\n", t[i].inf.peak_virtual_memory_size);
        fprintf(file, "<LOCKED MEMORY SIZE> %dKb\n", t[i].inf.locked_memory_size);
        fprintf(file, "<PINNED MEMORY SIZE> %dKb\n", t[i].inf.pinned_memory_size);
        fprintf(file, "<PEAK RESIDENT SET SIZE> %dKb\n", t[i].inf.peak_resident_set_size);
        fprintf(file, "<VIRTUAL MEMORY SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.virtual_memory_size.max, t[i].inf.virtual_memory_size.avg, t[i].inf.virtual_memory_size.min);
        fprintf(file, "<RESIDENT SET SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.resident_set_size.max, t[i].inf.resident_set_size.avg, t[i].inf.resident_set_size.min);
        fprintf(file, "<RESIDENT ANONYMOUS MEMORY SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.resident_anonymous_memory_size.max, t[i].inf.resident_anonymous_memory_size.avg, t[i].inf.resident_anonymous_memory_size.min);
        fprintf(file, "<RESIDENT FILE MAPPING SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.resident_file_mapping_size.max, t[i].inf.resident_file_mapping_size.avg, t[i].inf.resident_file_mapping_size.min);
        fprintf(file, "<DATA SEGMENT SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.data_segment_size.max, t[i].inf.data_segment_size.avg, t[i].inf.data_segment_size.min);
        fprintf(file, "<RESIDENT SHARED MEMORY SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.resident_shared_meory_size.max, t[i].inf.resident_shared_meory_size.avg, t[i].inf.resident_shared_meory_size.min);
        fprintf(file, "<STACK SEGMENT SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.stack_segment_size.max, t[i].inf.stack_segment_size.avg, t[i].inf.stack_segment_size.min);
        fprintf(file, "<TEXT SEGMENT SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.text_segment_size.max, t[i].inf.text_segment_size.avg, t[i].inf.text_segment_size.min);
        fprintf(file, "<SHARED LIBRARY CODE SIZE SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.shared_library_code_size.max, t[i].inf.shared_library_code_size.avg, t[i].inf.shared_library_code_size.min);
        fprintf(file, "<PAGE TABLE ENTRIES SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.page_table_entries_size.max, t[i].inf.page_table_entries_size.avg, t[i].inf.page_table_entries_size.min);
        fprintf(file, "<SWAPED-OUT VIRTUAL MEMORY SIZE>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.swaped_out_virtual_memory_size.max, t[i].inf.swaped_out_virtual_memory_size.avg, t[i].inf.swaped_out_virtual_memory_size.min);
        fprintf(file, "<HUGETLB MEMORY PORTIONS>\n");
        fprintf(file, "<maximum> %dKb\n<average> %.2lfKb\n<minimum> %dKb\n", t[i].inf.hugetlb_memory_portions.max, t[i].inf.hugetlb_memory_portions.avg, t[i].inf.hugetlb_memory_portions.min);
        fprintf(file, "<NUMBER OF THREADS>\n");
        fprintf(file, "<maximum> %d\n<average> %.2lf\n<minimum> %d\n", t[i].inf.number_of_threads_in_process.max, t[i].inf.number_of_threads_in_process.avg, t[i].inf.number_of_threads_in_process.min);
        fprintf(file, "\n\n\n---------------------------------------------------------------\n");
    }
    fclose(file);
}


proc* ReadGoodProcesses(char* path)
{
    FILE* file = fopen(path, "r");
    proc* p = NULL;
    int num_of_lines = NumberOfLinesInFile(path);
    char* str = NULL, *endptr;
    str = (char*)xmalloc(2048 * sizeof(char));
    p = (proc*)xmalloc(sizeof(proc) * num_of_lines);
    rewind(file);
    int i = 0;
    while(fgets(str, 2048, file))
    {
        size_t fp = find(str, "<PID>");
        size_t fn = find(str, "<NAME>");
        size_t fc = find(str, "<CMD>");

        p[i].pid = strtol(substr(fp + 5, fn - fp - 5, str), &endptr, 10);
        p[i].name = substr(fn + 6, fc - fn - 5, str);
        if(i != num_of_lines - 1)
            p[i].cmd = substr(fc + 5, strlen(str) - fc - 10, str);
        else
            p[i].cmd = substr(fc + 5, strlen(str) - fc - 9, str);
        i++;
    }

    fclose(file);
    return p;
}


totals* ReadActualProcesses(int *i)
{
    DIR* dir = opendir("/proc");
    FILE* file;
    struct dirent* direct = NULL;
    char path[128] = "path", *str = NULL,  *endptr;
    size_t f;
    totals* tList = NULL;
    tList = (totals*)xmalloc(1024 * sizeof(totals));
    str = (char*)xmalloc(2048 * sizeof(char));
    *i = 0;
    
    while((direct = readdir(dir)) != NULL)
    {
        if(direct->d_type == DT_DIR)
        {
            if(IsNumeric(direct->d_name))
            {
                // PID
                tList[*i].prc.pid = strtol(direct->d_name, &endptr, 10);
                sprintf(path, "/proc/%s/cmdline", direct->d_name);
                if((file = fopen(path, "r")) == NULL)
                {
                    fprintf(stderr, "Error: Cannot open the file!");
                    exit(EXIT_FAILURE);
                }
                // CMD
                fgets(str, 2048, file);
                str = Beautify(str);
                tList[*i].prc.cmd = str;
                str = (char*)calloc(2048, sizeof(char));

                // TIME & NUMBER OF SCANS
                tList[*i].inf.number_of_scans = 1;
                time_t t = time(NULL);
                struct tm* tm = localtime(&t);
                sprintf(str, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                tList[*i].inf.first_read = str;
                tList[*i].inf.last_read = str;
                str = (char*)calloc(2048, sizeof(char));
                
                fclose(file);
                sprintf(path, "/proc/%s/status", direct->d_name);
                if((file = fopen(path, "r")) == NULL)
                {
                    fprintf(stderr, "Error: Cannot open the file!");
                    exit(EXIT_FAILURE);
                }

                // NAME
                fgets(str, 2048, file);
                f = find(str, "Name:\t");
                str = substr(f + 6, strlen(str) - f - 6, str);
                tList[*i].prc.name = str;
                str = (char*)calloc(2048, sizeof(char));

                while(fgets(str, 2048, file))
                {
                    if(!find(str, "Umask:\t"))
                    {    
                        tList[*i].inf.umask = substr(7, strlen(str) - 7, str);
                    }
                    else if(!find(str, "State:\t"))
                    {
                        tList[*i].inf.last_state = substr(f + 7, strlen(str) - f - 7, str);
                    }
                    else if(!find(str, "FDSize:\t"))
                    {
                        tList[*i].inf.file_description_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                    }
                    else if(!find(str, "VmPeak:\t"))
                    {
                        tList[*i].inf.peak_virtual_memory_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                    }
                    else if(!find(str, "VmLck:\t"))
                    {
                        tList[*i].inf.locked_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                    }
                    else if(!find(str, "VmPin:\t"))
                    {    
                        tList[*i].inf.pinned_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                    }
                    else if(!find(str, "VmSize:\t"))
                    {
                        tList[*i].inf.virtual_memory_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                        tList[*i].inf.virtual_memory_size.max = tList[*i].inf.virtual_memory_size.min;
                        tList[*i].inf.virtual_memory_size.avg = tList[*i].inf.virtual_memory_size.min;
                    }

                    else if(!find(str, "VmHWM:\t"))
                    { 
                        tList[*i].inf.hugetlb_memory_portions.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                        tList[*i].inf.hugetlb_memory_portions.max = tList[*i].inf.hugetlb_memory_portions.min;
                        tList[*i].inf.hugetlb_memory_portions.avg = tList[*i].inf.hugetlb_memory_portions.min;
                    }

                    else if(!find(str, "VmRSS:\t"))
                    {
                        tList[*i].inf.resident_set_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                        tList[*i].inf.resident_set_size.max = tList[*i].inf.resident_set_size.min;
                        tList[*i].inf.resident_set_size.avg = tList[*i].inf.resident_set_size.min;
                    }

                    else if(!find(str, "RssAnon:\t"))
                    {
                        tList[*i].inf.resident_anonymous_memory_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                        tList[*i].inf.resident_anonymous_memory_size.max = tList[*i].inf.resident_anonymous_memory_size.min;
                        tList[*i].inf.resident_anonymous_memory_size.avg = tList[*i].inf.resident_anonymous_memory_size.min;
                    }
                    else if(!find(str, "RssFile:\t"))
                    {
                        tList[*i].inf.resident_file_mapping_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                        tList[*i].inf.resident_file_mapping_size.max = tList[*i].inf.resident_file_mapping_size.min;
                        tList[*i].inf.resident_file_mapping_size.avg = tList[*i].inf.resident_file_mapping_size.min;
                    }

                    else if(!find(str, "RssShmem:\t"))
                    {
                        tList[*i].inf.resident_shared_meory_size.min = strtol(substr(f + 10, strlen(str) - f - 10, str), &endptr, 10);
                        tList[*i].inf.resident_shared_meory_size.max = tList[*i].inf.resident_shared_meory_size.min;
                        tList[*i].inf.resident_shared_meory_size.avg = tList[*i].inf.resident_shared_meory_size.min;
                    }

                    else if(!find(str, "VmData:\t"))
                    {
                        tList[*i].inf.data_segment_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                        tList[*i].inf.data_segment_size.max = tList[*i].inf.data_segment_size.min;
                        tList[*i].inf.data_segment_size.avg = tList[*i].inf.data_segment_size.min;
                    }

                    else if(!find(str, "VmStk:\t"))
                    {
                        tList[*i].inf.stack_segment_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                        tList[*i].inf.stack_segment_size.max = tList[*i].inf.stack_segment_size.min;
                        tList[*i].inf.stack_segment_size.avg = tList[*i].inf.stack_segment_size.min;
                    }

                    else if(!find(str, "VmExe:\t"))
                    {
                        tList[*i].inf.shared_library_code_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                        tList[*i].inf.shared_library_code_size.max = tList[*i].inf.shared_library_code_size.min;
                        tList[*i].inf.shared_library_code_size.avg = tList[*i].inf.shared_library_code_size.min;
                    }

                    else if(!find(str, "VmPTE:\t"))
                    {
                        tList[*i].inf.page_table_entries_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                        tList[*i].inf.page_table_entries_size.max = tList[*i].inf.page_table_entries_size.min;
                        tList[*i].inf.page_table_entries_size.avg = tList[*i].inf.page_table_entries_size.min;
                    }

                    else if(!find(str, "VmSwap:\t"))
                    {
                        tList[*i].inf.swaped_out_virtual_memory_size.min = strtol(str = substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                        tList[*i].inf.swaped_out_virtual_memory_size.max = tList[*i].inf.swaped_out_virtual_memory_size.min;
                        tList[*i].inf.swaped_out_virtual_memory_size.avg = tList[*i].inf.swaped_out_virtual_memory_size.min;
                    }

                    else if(!find(str, "Threads:\t"))
                    {
                        tList[*i].inf.number_of_threads_in_process.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                        tList[*i].inf.number_of_threads_in_process.max = tList[*i].inf.number_of_threads_in_process.min;
                        tList[*i].inf.number_of_threads_in_process.avg = tList[*i].inf.number_of_threads_in_process.min;
                    }

                    else continue;
                }
                ++(*i);
                fclose(file);
            }
        }
        
        
    }
    closedir(dir);
    
    return tList;
}



totals* RepeatRead(int* number_of_processes, totals* previous_processes)
{
    DIR* dir = opendir("/proc");
    rewinddir(dir);
    FILE* file;
    char path[128], *str = NULL, *endptr;
    struct dirent* direct = NULL;
    size_t f;
    totals* tList = NULL;
    tList = (totals*)xmalloc(1024 * sizeof(totals));
    str = (char*)xmalloc(2048 * sizeof(char));
    int i = 0, p = *number_of_processes;


    while((direct = readdir(dir)) != NULL)
    {
        if(direct->d_type == DT_DIR)
        {
            if(IsNumeric(direct->d_name))
            {
                sprintf(path, "/proc/%s/status", direct->d_name);
                      
                if((file = fopen(path, "r")) == NULL)
                {
                    fprintf(stderr, "Error: Cannot open the file status!");
                    exit(EXIT_FAILURE);
                }
                
                //Name
                fgets(str, 2048, file);
                f = find(str, "Name:\t");
                str = substr(f + 6, strlen(str) - f - 6, str);
                tList[i].prc.name = str;
                
                if(AlreadyExists(p, strtol(direct->d_name, &endptr, 10), str, previous_processes))
                {
                    str = (char*)calloc(2048, sizeof(char));
                    int c = 0;
                    while (previous_processes[c].prc.pid != atoi(direct->d_name)) c++;

                    // NUMBER OF SCANS INCREMENTING
                    ++previous_processes[c].inf.number_of_scans;
                    

                    // TIME REFRESH
                    time_t t = time(NULL);
                    struct tm* tm = localtime(&t);
                    sprintf(str, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                    previous_processes[c].inf.last_read = str;
                    str = (char*)calloc(2048, sizeof(char));
                    
                    tList[i] = previous_processes[c];
                    
                    // STATISTIC REFRESH
                    int actual = 0;
                    while(fgets(str, 2048, file))
                    {
                        if(!find(str, "VmSize:\t"))
                        {
                            actual = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                            tList[i].inf.virtual_memory_size = RefreshStatistics(tList[i].inf.virtual_memory_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmHWM:\t"))
                        { 
                            actual = strtol(substr(f + 7, strlen(str) - f - 7, str) ,&endptr, 10);
                            tList[i].inf.hugetlb_memory_portions = RefreshStatistics(tList[i].inf.hugetlb_memory_portions, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmRSS:\t"))
                        {
                            actual = strtol(substr(f + 7, strlen(str) - f - 7, str) ,&endptr, 10);
                            tList[i].inf.resident_set_size = RefreshStatistics(tList[i].inf.resident_set_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "RssAnon:\t"))
                        {
                            actual = strtol(substr(f + 9, strlen(str) - f - 9, str) ,&endptr, 10);
                            tList[i].inf.resident_anonymous_memory_size = RefreshStatistics(tList[i].inf.resident_anonymous_memory_size, actual, tList[i].inf.number_of_scans);
                        }
                        else if(!find(str, "RssFile:\t"))
                        {
                            actual = strtol(substr(f + 9, strlen(str) - f - 9, str) ,&endptr, 10);
                            tList[i].inf.resident_file_mapping_size = RefreshStatistics(tList[i].inf.resident_file_mapping_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "RssShmem:\t"))
                        {
                            actual = strtol(substr(f + 10, strlen(str) - f - 10, str) ,&endptr, 10);
                            tList[i].inf.resident_shared_meory_size = RefreshStatistics(tList[i].inf.resident_shared_meory_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmData:\t"))
                        {
                            actual = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                            tList[i].inf.data_segment_size = RefreshStatistics(tList[i].inf.data_segment_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmStk:\t"))
                        {
                            actual = strtol(substr(f + 7, strlen(str) - f - 7, str) ,&endptr, 10);
                            tList[i].inf.stack_segment_size = RefreshStatistics(tList[i].inf.stack_segment_size, actual, tList[i].inf.number_of_scans);
                            
                        }

                        else if(!find(str, "VmExe:\t"))
                        {
                            actual = strtol(substr(f + 7, strlen(str) - f - 7, str) ,&endptr, 10);
                            tList[i].inf.shared_library_code_size = RefreshStatistics(tList[i].inf.shared_library_code_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmPTE:\t"))
                        {
                            actual = strtol(substr(f + 7, strlen(str) - f - 7, str) ,&endptr, 10);
                            tList[i].inf.page_table_entries_size = RefreshStatistics(tList[i].inf.page_table_entries_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "VmSwap:\t"))
                        {
                            actual = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                            tList[i].inf.swaped_out_virtual_memory_size = RefreshStatistics(tList[i].inf.swaped_out_virtual_memory_size, actual, tList[i].inf.number_of_scans);
                        }

                        else if(!find(str, "Threads:\t"))
                        {
                            actual = strtol(substr(f + 9, strlen(str) - f - 9, str) ,&endptr, 10);
                            tList[i].inf.number_of_threads_in_process = RefreshStatistics(tList[i].inf.number_of_threads_in_process, actual, tList[i].inf.number_of_scans);
                        }

                        else continue;
                    }
                }
                else
                {
                    if(OnlyPidExists(p, atoi(direct->d_name), previous_processes))
                    {
                        str = (char*)calloc(2048, sizeof(char));

                        // TIME & NUMBER OF SCANS
                        tList[i].inf.number_of_scans = 1;
                        time_t t = time(NULL);
                        struct tm* tm = localtime(&t);
                        sprintf(str, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                        tList[i].inf.first_read = str;
                        tList[i].inf.last_read = str;
                        str = (char*)calloc(2048, sizeof(char));

                        while(fgets(str, 2048, file))
                        {
                            if(!find(str, "Umask:\t"))
                            {    
                                tList[i].inf.umask = substr(7, strlen(str) - 7, str);
                            }
                            else if(!find(str, "State:\t"))
                            {
                                tList[i].inf.last_state = substr(f + 7, strlen(str) - f - 7, str);
                            }
                            else if(!find(str, "FDSize:\t"))
                            {
                                tList[i].inf.file_description_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                            }
                            else if(!find(str, "VmPeak:\t"))
                            {
                                tList[i].inf.peak_virtual_memory_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                            }
                            else if(!find(str, "VmLck:\t"))
                            {
                                tList[i].inf.locked_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                            }
                            else if(!find(str, "VmPin:\t"))
                            {    
                                tList[i].inf.pinned_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                            }
                            else if(!find(str, "VmSize:\t"))
                            {
                                tList[i].inf.virtual_memory_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                                tList[i].inf.virtual_memory_size.max = tList[i].inf.virtual_memory_size.min;
                                tList[i].inf.virtual_memory_size.avg = tList[i].inf.virtual_memory_size.min;
                            }

                            else if(!find(str, "VmHWM:\t"))
                            { 
                                tList[i].inf.hugetlb_memory_portions.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.hugetlb_memory_portions.max = tList[i].inf.hugetlb_memory_portions.min;
                                tList[i].inf.hugetlb_memory_portions.avg = tList[i].inf.hugetlb_memory_portions.min;
                            }

                            else if(!find(str, "VmRSS:\t"))
                            {
                                tList[i].inf.resident_set_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.resident_set_size.max = tList[i].inf.resident_set_size.min;
                                tList[i].inf.resident_set_size.avg = tList[i].inf.resident_set_size.min;
                            }

                            else if(!find(str, "RssAnon:\t"))
                            {
                                tList[i].inf.resident_anonymous_memory_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.resident_anonymous_memory_size.max = tList[i].inf.resident_anonymous_memory_size.min;
                                tList[i].inf.resident_anonymous_memory_size.avg = tList[i].inf.resident_anonymous_memory_size.min;
                            }
                            else if(!find(str, "RssFile:\t"))
                            {
                                tList[i].inf.resident_file_mapping_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.resident_file_mapping_size.max = tList[i].inf.resident_file_mapping_size.min;
                                tList[i].inf.resident_file_mapping_size.avg = tList[i].inf.resident_file_mapping_size.min;
                            }

                            else if(!find(str, "RssShmem:\t"))
                            {
                                tList[i].inf.resident_shared_meory_size.min = strtol(substr(f + 10, strlen(str) - f - 10, str), &endptr, 10);
                                tList[i].inf.resident_shared_meory_size.max = tList[i].inf.resident_shared_meory_size.min;
                                tList[i].inf.resident_shared_meory_size.avg = tList[i].inf.resident_shared_meory_size.min;
                            }

                            else if(!find(str, "VmData:\t"))
                            {
                                tList[i].inf.data_segment_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                                tList[i].inf.data_segment_size.max = tList[i].inf.data_segment_size.min;
                                tList[i].inf.data_segment_size.avg = tList[i].inf.data_segment_size.min;
                            }

                            else if(!find(str, "VmStk:\t"))
                            {
                                tList[i].inf.stack_segment_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.stack_segment_size.max = tList[i].inf.stack_segment_size.min;
                                tList[i].inf.stack_segment_size.avg = tList[i].inf.stack_segment_size.min;
                            }

                            else if(!find(str, "VmExe:\t"))
                            {
                                tList[i].inf.shared_library_code_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.shared_library_code_size.max = tList[i].inf.shared_library_code_size.min;
                                tList[i].inf.shared_library_code_size.avg = tList[i].inf.shared_library_code_size.min;
                            }

                            else if(!find(str, "VmPTE:\t"))
                            {
                                tList[i].inf.page_table_entries_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.page_table_entries_size.max = tList[i].inf.page_table_entries_size.min;
                                tList[i].inf.page_table_entries_size.avg = tList[i].inf.page_table_entries_size.min;
                            }

                            else if(!find(str, "VmSwap:\t"))
                            {
                                tList[i].inf.swaped_out_virtual_memory_size.min = strtol(str = substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                                tList[i].inf.swaped_out_virtual_memory_size.max = tList[i].inf.swaped_out_virtual_memory_size.min;
                                tList[i].inf.swaped_out_virtual_memory_size.avg = tList[i].inf.swaped_out_virtual_memory_size.min;
                            }

                            else if(!find(str, "Threads:\t"))
                            {
                                tList[i].inf.number_of_threads_in_process.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.number_of_threads_in_process.max = tList[i].inf.number_of_threads_in_process.min;
                                tList[i].inf.number_of_threads_in_process.avg = tList[i].inf.number_of_threads_in_process.min;
                            }
                            else continue;

                            // CMD
                            fclose(file);
                            sprintf(path, "/proc/%s/cmdline", direct->d_name);
                            if((file = fopen(path, "r")) == NULL)
                            {
                                fprintf(stderr, "Error: Cannot open the file!");
                                exit(EXIT_FAILURE);
                            }
                            fgets(str, 2048, file);
                            str = Beautify(str);
                            tList[i].prc.cmd = str;
                            str = (char*)calloc(2048, sizeof(char));
                        }
                    }
                    else
                    {
                        str = (char*)calloc(2048, sizeof(char));
                        
                        // TIME & NUMBER OF SCANS
                        tList[i].inf.number_of_scans = 1;
                        time_t t = time(NULL);
                        struct tm* tm = localtime(&t);
                        sprintf(str, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                        tList[i].inf.first_read = str;
                        tList[i].inf.last_read = str;
                        str = (char*)calloc(2048, sizeof(char));

                        while(fgets(str, 2048, file))
                        {
                            if(!find(str, "Umask:\t"))
                            {    
                                tList[i].inf.umask = substr(7, strlen(str) - 7, str);
                            }
                            else if(!find(str, "State:\t"))
                            {
                                tList[i].inf.last_state = substr(f + 7, strlen(str) - f - 7, str);
                            }
                            else if(!find(str, "FDSize:\t"))
                            {
                                tList[i].inf.file_description_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                            }
                            else if(!find(str, "VmPeak:\t"))
                            {
                                tList[i].inf.peak_virtual_memory_size = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                            }
                            else if(!find(str, "VmLck:\t"))
                            {
                                tList[i].inf.locked_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                            }
                            else if(!find(str, "VmPin:\t"))
                            {    
                                tList[i].inf.pinned_memory_size = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                            }
                            else if(!find(str, "VmSize:\t"))
                            {
                                tList[i].inf.virtual_memory_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str) ,&endptr, 10);
                                tList[i].inf.virtual_memory_size.max = tList[i].inf.virtual_memory_size.min;
                                tList[i].inf.virtual_memory_size.avg = tList[i].inf.virtual_memory_size.min;
                            }

                            else if(!find(str, "VmHWM:\t"))
                            { 
                                tList[i].inf.hugetlb_memory_portions.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.hugetlb_memory_portions.max = tList[i].inf.hugetlb_memory_portions.min;
                                tList[i].inf.hugetlb_memory_portions.avg = tList[i].inf.hugetlb_memory_portions.min;
                            }

                            else if(!find(str, "VmRSS:\t"))
                            {
                                tList[i].inf.resident_set_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.resident_set_size.max = tList[i].inf.resident_set_size.min;
                                tList[i].inf.resident_set_size.avg = tList[i].inf.resident_set_size.min;
                            }

                            else if(!find(str, "RssAnon:\t"))
                            {
                                tList[i].inf.resident_anonymous_memory_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.resident_anonymous_memory_size.max = tList[i].inf.resident_anonymous_memory_size.min;
                                tList[i].inf.resident_anonymous_memory_size.avg = tList[i].inf.resident_anonymous_memory_size.min;
                            }
                            else if(!find(str, "RssFile:\t"))
                            {
                                tList[i].inf.resident_file_mapping_size.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.resident_file_mapping_size.max = tList[i].inf.resident_file_mapping_size.min;
                                tList[i].inf.resident_file_mapping_size.avg = tList[i].inf.resident_file_mapping_size.min;
                            }

                            else if(!find(str, "RssShmem:\t"))
                            {
                                tList[i].inf.resident_shared_meory_size.min = strtol(substr(f + 10, strlen(str) - f - 10, str), &endptr, 10);
                                tList[i].inf.resident_shared_meory_size.max = tList[i].inf.resident_shared_meory_size.min;
                                tList[i].inf.resident_shared_meory_size.avg = tList[i].inf.resident_shared_meory_size.min;
                            }

                            else if(!find(str, "VmData:\t"))
                            {
                                tList[i].inf.data_segment_size.min = strtol(substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                                tList[i].inf.data_segment_size.max = tList[i].inf.data_segment_size.min;
                                tList[i].inf.data_segment_size.avg = tList[i].inf.data_segment_size.min;
                            }

                            else if(!find(str, "VmStk:\t"))
                            {
                                tList[i].inf.stack_segment_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.stack_segment_size.max = tList[i].inf.stack_segment_size.min;
                                tList[i].inf.stack_segment_size.avg = tList[i].inf.stack_segment_size.min;
                            }

                            else if(!find(str, "VmExe:\t"))
                            {
                                tList[i].inf.shared_library_code_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.shared_library_code_size.max = tList[i].inf.shared_library_code_size.min;
                                tList[i].inf.shared_library_code_size.avg = tList[i].inf.shared_library_code_size.min;
                            }

                            else if(!find(str, "VmPTE:\t"))
                            {
                                tList[i].inf.page_table_entries_size.min = strtol(substr(f + 7, strlen(str) - f - 7, str), &endptr, 10);
                                tList[i].inf.page_table_entries_size.max = tList[i].inf.page_table_entries_size.min;
                                tList[i].inf.page_table_entries_size.avg = tList[i].inf.page_table_entries_size.min;
                            }

                            else if(!find(str, "VmSwap:\t"))
                            {
                                tList[i].inf.swaped_out_virtual_memory_size.min = strtol(str = substr(f + 8, strlen(str) - f - 8, str), &endptr, 10);
                                tList[i].inf.swaped_out_virtual_memory_size.max = tList[i].inf.swaped_out_virtual_memory_size.min;
                                tList[i].inf.swaped_out_virtual_memory_size.avg = tList[i].inf.swaped_out_virtual_memory_size.min;
                            }

                            else if(!find(str, "Threads:\t"))
                            {
                                tList[i].inf.number_of_threads_in_process.min = strtol(substr(f + 9, strlen(str) - f - 9, str), &endptr, 10);
                                tList[i].inf.number_of_threads_in_process.max = tList[i].inf.number_of_threads_in_process.min;
                                tList[i].inf.number_of_threads_in_process.avg = tList[i].inf.number_of_threads_in_process.min;
                            }
                            else continue;
                        }
                        ++(*number_of_processes);
                        fclose(file);
                        sprintf(path, "/proc/%s/cmdline", direct->d_name);
                        if((file = fopen(path, "r")) == NULL)
                        {
                            fprintf(stderr, "Error: Cannot open the file!");
                            exit(EXIT_FAILURE);
                        }
                        fgets(str, 2048, file);
                        str = Beautify(str);
                        tList[i].prc.cmd = str;
                        str = (char*)calloc(2048, sizeof(char));
                    }
                }
                ++i;
                fclose(file);
            }
        }

        
    }
    closedir(dir);
    
    return tList;
}


void Scan(totals* global_list, proc* proc_good, int n, int num)
{
    int i, j, firstCall = 1;
    _Bool b = 0;

    for(i = 0; i<num; ++i)
    {
        b = 0;
        for(j = 0; j<n; ++j)
        {
            if(strcmp(global_list[i].prc.name, proc_good[j].name) == 0)
            {
                b = 0;
                break;
            }
            else
            {
                b = 1;
            }
            // printf("%s == %s | %d\n", global_list[i].prc.name, proc_good[j].name, strcmp(global_list[i].prc.name, proc_good[j].name) == 0);
        }
        if(b)
        {
            // kill(global_list[i].prc.pid, SIGKILL);
            WriteProcess(global_list[i].prc, firstCall);
            firstCall = 0;
        }
            
    }
}