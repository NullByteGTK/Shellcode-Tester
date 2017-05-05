/*
* Shellcode Tester
* Written by: NullByte
* Github: NullByteGTK
* Contact: nullbytegtk@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *get_input(unsigned long long *counter); //A simple function for getting user input

int main(){
	setbuf(stdout,NULL);
	unsigned long long length = 0; //Length of shell
	unsigned long long sh = 0; //This will be used as a counter for translating input into its assembly code value (ex: \xa0 => 160) 
	printf("Shellcode: ");
	char *shellcode = get_input(&length);

	if((length % 4) != 0){ //Since it expects shellcode in \xaa format no matter what shellcode you want to use it will be dividable by four
		puts("Your shellcode must be like \\xde\\xad\\xbe\\xef");
		exit(0);
	}

	//The following for loop translates input into its assembly code value
	for(unsigned long long i = 2;i < length;i += 4){
		int temp = 0;
    	if(shellcode[i]-96 > 0){
      		temp += (10+(shellcode[i]-97))*16;
    	}else{
      		temp += (shellcode[i]-48)*16;
    	}
    	if(shellcode[i+1]-96 > 0){
      		temp += 10+(shellcode[i+1]-97);
    	}else{
      		temp += shellcode[i+1]-48;
    	}
    	shellcode[sh++] = temp;
	}

	shellcode[sh++] = 0xc3;
	//The line above will make the last assembly instruction to "ret" so if your shellcode doesn't mess with the stack it will return to main function and will not raise a segfault 
	
	for(;sh<length;sh++){ //This for loop will zero out the input because we don't need it anymore
		shellcode[sh] = 0;
	}

	printf("Shellcode address: %p - Length:%llu\n",shellcode,(length/4)); //Prints shellcode's address on heap + its length
	(*(void(*)()) shellcode)(); //Calls shellcode
	free(shellcode);
	return 0;
}

char *get_input(unsigned long long *counter){
	unsigned int add=128;
	unsigned long long base = 256,point = 0;
	unsigned char buff;
	char *input_buffer;
	input_buffer = (char *)malloc(base); //Allocate 256bytes on heap
	while(buff = getchar()){ //Get input char by char
		if(buff == '\n'){ //If input char was newline add a null terminator to the end of the buffer and return its address
	    	if(point == base){
	        	input_buffer = (char *)realloc(input_buffer,base+add);
	        	base += add;
	      	}
	        input_buffer[point] = 0;
	        break;
	    }else{
	      if(point == base){ //If input length was bigger than the allocated buffer reallocate it
	        input_buffer = (char *)realloc(input_buffer,base+add);
	        base += add;
	      }
	      input_buffer[point] = buff;
	      point++;
	    }
	}
	*counter = point; 
	return input_buffer;
}
