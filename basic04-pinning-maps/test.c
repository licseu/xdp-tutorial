#include <stdio.h>
void main() {
	int a = 1;
	unsigned long long *b = &a;
	printf("the val is b is %p, b+1 is %p\n", b, b+1);
}
