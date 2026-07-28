#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_QUESTIONS 32

struct question {
    void (*print)(struct question *q);
    char padding[20];
    char *text;
};

static const char banner[] =
"  _   _       _        _____ ______ ______  Classic\n"
" | \\ | |     | |      |  __ \\___  /| ___ \\        \n"
" |  \\| | ___ | |_ ___ | |__) | / / | |_/ /        \n"
" | . ` |/ _ \\| __/ _ \\|  ___/ / /  |  __/         \n"
" | |\\  | (_) | ||  __/| |   ./ /___| |            \n"
" |_| \\_|\\___/ \\__\\___||_|   \\_____/|_|            \n";

int number_questions;
struct question *questions[MAX_QUESTIONS];

static void flush(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

void print_banner(void) {
    puts(banner);
}

void print_question(struct question *q) {
    puts("Dobby has a question for you");
    printf("I have the answer perhaps: '%s'", q->text);
}

struct question *get_question(void) {
    char idbuf[4] = {0};
    printf("Enter question id: ");
    if (!fgets(idbuf, sizeof(idbuf), stdin)) exit(0);
    int id = atoi(idbuf);
    if (id < 0 || id >= number_questions) {
        puts("Invalid ID");
        _exit(0);
    }
    return questions[id];
}

void create_question(void) {
    if (number_questions > 31) {
        puts("Too many questions created...");
        return;
    }
    puts("Creating new question...");
    struct question *q = malloc(sizeof(struct question));   /* 0x1c request -> 0x20 chunk on i386 */
    if (!q) { puts("Failed to create new question"); return; }
    q->text = malloc(0x14);                                 /* 0x14 request -> 0x20 chunk on i386 */
    if (!q->text) { puts("Failed to create new question"); free(q); return; }
    q->print = print_question;
    memset(q->padding, 0, sizeof(q->padding));
    printf("Created new question. ID %d", number_questions);
    questions[number_questions++] = q;
}

void delete_question(void) {
    struct question *q = get_question();
    free(q->text);     /* classic bug: stale pointer remains in questions[] */
    free(q);           /* and q->text is not cleared */
    puts("Question deleted");
}

void set_question(void) {
    struct question *q = get_question();
    printf("Enter your question: ");
    fgets(q->text, 0x50, stdin);      /* intentional heap overflow / arbitrary write after poisoning */
    puts("question set... ");
}

void ask_question(void) {
    struct question *q = get_question();
    q->print(q);
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
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    print_banner();
    while (menu()) {}
    return 0;
}
