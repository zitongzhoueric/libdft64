/*
 * instrace_test.c
 *
 * A simple test program to demonstrate the instrace Pin tool.
 * This program performs basic arithmetic and function calls.
 */

#include <stdio.h>

// Simple function to add two numbers
int add(int a, int b) {
    return a + b;
}

// Simple function to multiply two numbers
int multiply(int a, int b) {
    return a * b;
}

int main(int argc, char *argv[]) {
    printf("Starting instrace test program...\n");

    // Perform some basic operations
    int x = 10;
    int y = 20;

    int sum = add(x, y);
    printf("Sum: %d + %d = %d\n", x, y, sum);

    int product = multiply(x, y);
    printf("Product: %d * %d = %d\n", x, y, product);

    // Loop example
    int total = 0;
    for (int i = 0; i < 5; i++) {
        total += i;
    }
    printf("Total from loop: %d\n", total);

    printf("Test program finished.\n");
    return 0;
}
