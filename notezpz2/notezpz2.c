#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_QUESTIONS 32

struct question {
    unsigned long a;
    unsigned long b;
    unsigned long c;
    char *text;
    char pad[0x500];
};

static const char banner[] =
"  _   _       _        _____ ______ ______ ___  \n"
" | \\ | |     | |      |  __ \\___  /| ___ \\__ \\ \n"
" |  \\| | ___ | |_ ___ | |__) | / / | |_/ /  ) |\n"
" | . ` |/ _ \\| __/ _ \\|  ___/ / /  |  __/  / / \n"
" | |\\  | (_) | ||  __/| |   ./ /___| |    / /_ \n"
" |_| \\_|\\___/ \\__\\___||_|   \\_____/|_|   |____|\n";

int number_questions;
struct question *questions[MAX_QUESTIONS];

static void flush(void) { int c; while ((c = getchar()) != '\n' && c != EOF) {} }
void print_banner(void) { puts(banner); }

void print_question(struct question *q) {
    puts("Dobby has a question for you");
    printf("I have the answer perhaps: '%s'", q->text);
}

void create_question(void) {
    if (number_questions > 31) { puts("Too many questions created..."); return; }
    puts("Creating new question...");
    struct question *q = malloc(0x520);
    if (!q) { puts("Failed to create new question"); return; }
    q->text = malloc(0x410);
    if (!q->text) { puts("Failed to create new question"); free(q); return; }
    printf("Created new question. ID %d", number_questions);
    questions[number_questions++] = q;
}

struct question *get_question(void) {
    char idbuf[4] = {0};
    printf("Enter question id: ");
    fgets(idbuf, sizeof(idbuf), stdin);
    int id = atoi(idbuf);
    if (id < 0 || id >= number_questions) { puts("Invalid ID"); _exit(0); }
    return questions[id];
}

void delete_question(void) {
    struct question *q = get_question();
    free(q->text);
    free(q);
    puts("Question deleted");
}

void set_question(void) {
    struct question *q = get_question();
    printf("Enter your question: ");
    fgets(q->text, 0x78, stdin); /* arbitrary-write primitive after UAF metadata corruption */
    puts("question set... ");
}

void ask_question(void) {
    struct question *q = get_question();
    print_question(q);
}

int menu(void) {
    putchar('\n');
    puts("[C]reate new question");
    puts("[D]elete question");
    puts("[S]et question");
    puts("[A]sk question");
    puts("[Q]uit");
    putchar('\n');
    printf("Enter your choice, (or press enter to refresh): ");
    int ch = getchar();
    if (ch == EOF) return 0;
    switch (ch) {
        case 'C': case 'c': flush(); create_question(); break;
        case 'D': case 'd': flush(); delete_question(); break;
        case 'S': case 's': flush(); set_question(); break;
        case 'A': case 'a': flush(); ask_question(); break;
        case 'Q': case 'q': flush(); return 0;
        case '\n': break;
        default: putchar('\n'); break;
    }
    return 1;
}

int main(void) {
    setbuf(stdout, NULL);
    print_banner();
    while (menu()) {}
    return 0;
}
