int quarantine_file(const char* file_path, const char* matched_rules);
int restore_file(const char* filename);

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <quarantine|restore> <file>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "quarantine") == 0)
        return quarantine_file(argv[2], NULL);
    else if (strcmp(argv[1], "restore") == 0)
        return restore_file(argv[2]);
    return 1;
}
/* This is to keep quarantine modular and run it straight from the command line. 

  nano quarantine_cli.c   # paste the above, save with Ctrl+X → Y → Enter

gcc engine.c quarantine.c -o engine -lyara
gcc quarantine.c quarantine_cli.c -o quarantine
gcc rtm.c -o rtm -lpthread 
S15 */
