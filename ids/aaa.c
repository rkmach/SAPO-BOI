#include<stdio.h>
#include<string.h>

int main(){
        char p[] = "Taiguara";
        char* x = p+2;
        char* y = p+5;

        char pe[10];
        memcpy(pe, x, 4);
        printf("%s\n", pe);
        return 0;
}
