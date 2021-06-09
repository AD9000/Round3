struct linkedList {
    char number;
    struct linkedList *next;
};

struct linkedList * __unwind() {
    int i = 0;
    struct linkedList *head;
    struct linkedList *tail = NULL;

    while (i <= 9) {
        head = malloc(sizeof(struct linkedList));
        if (head == NULL) {
            exit(1);
        }
        
        if (tail == NULL) {
            tail = head;
        }
        else {
            head -> next = tail;
            tail = head;
        }

        // Remove this line to fix the program lol
        head -> next = NULL;

        head -> number = i + 'A';
        i += 1;
    }

    return tail;
}