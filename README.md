# Procces-Reader
Simple Antivirus-like program

Program for linux made in C. Reads all the actual processes put them in a file with all the information like PID, Name and CMD. Can be launched using a loop by specifying a parameter in cmd line when launching the program. Takes a list of processes of that are allowed to run on the system, if the processes are not in the list, the programs calls SIG_KILL.
