#include "header.h"


int main(int argc, char* argv[]){
    int rep, time, number_of_processes, number_of_gp = NumberOfLinesInFile("proc_good.txt");
    _Bool unlimited;
    totals* global_list = NULL;
    proc* proc_good = NULL;
    
    if(argc == 2)
    {
        rep = atoi(argv[1]);
        time = 0;
    }
    else if(argc == 3)
    {
        rep = atoi(argv[1]);
        time = atoi(argv[2]);
    }
    else
    {
        fprintf(stderr, "Error: Incorrect number of arguments!");
        exit(EXIT_FAILURE);
    }
    if(rep == 0) unlimited = 1;

    proc_good = (proc*)xmalloc(number_of_gp * sizeof(proc));
    proc_good = ReadGoodProcesses("proc_good.txt");

    while(rep > 0 || unlimited)
    {
        if(rep == atoi(argv[1]))
        {
            global_list = ReadActualProcesses(&number_of_processes);
        }
        else
        {
            global_list = RepeatRead(&number_of_processes, global_list);
        }
        PrintActuaProcesses(global_list, number_of_processes);
        Scan(global_list, proc_good, number_of_gp, number_of_processes);
        
        wait(time);
        rep--;
        
    }

    if(global_list) free(global_list); global_list = 0;

    return 0;
}