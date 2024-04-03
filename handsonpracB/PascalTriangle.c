#include <stdio.h>

// Function to calculate binomial coefficient
int binomialCoeff(int n, int k) {
    int res = 1;
    if (k > n - k)
        k = n - k;
    for (int i = 0; i < k; ++i) {
        res *= (n - i);
        res /= (i + 1);
    }
    return res;
}

// Function to print Pascal's Triangle
void printPascalTriangle(int n) {
    for (int line = 0; line < n; ++line) {
        // Print spaces for alignment
        for (int i = 0; i < n - line - 1; ++i)
            printf(" ");
        
        // Print elements in current line
        for (int i = 0; i <= line; ++i)
            printf("%d ", binomialCoeff(line, i));
        
        printf("\n");
    }
}

int main() {
    int numRows;

    // Ask the user to input the number of rows
    printf("Enter the number of rows for Pascal's Triangle: ");
    scanf("%d", &numRows);

    // Print Pascal's Triangle
    printPascalTriangle(numRows);

    return 0;
}