
TARGS := tiny_loader_ex1 tiny_loader_ex2

all: $(TARGS)

tiny_loader_ex1: main.c instructor.c  
	gcc -Wall $^ -g -DINSTRUCTOR_EX1 -o $@ 

tiny_loader_ex2: main.c instructor.c  
	gcc -Wall $^ -g -DINSTRUCTOR_EX2 -o $@ 

clean:
	rm -f $(TARGS)