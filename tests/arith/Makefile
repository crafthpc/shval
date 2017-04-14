TOOL_PATH=../../tools

main: main.c
	gcc -g -O2 -Wall -I$(TOOL_PATH) -o main main.c $(TOOL_PATH)/obj-intel64/shvalrt.a

clean:
	rm -f main
