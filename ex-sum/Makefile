# should point to Pin installation
PIN_ROOT=$(HOME)/opt/pin-2.14-71313-gcc.4.4.7-linux

TOOL_PATH=../tools

PIN=$(PIN_ROOT)/pin
FLAGS=-s

default: main

run: main
	@rm -f *.log
	@echo -e "\n===  Native 32-bit floating point  ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-native32.so $(FLAGS) -- ./main
	@echo -e "\n===  Native 64-bit floating point  ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-native64.so $(FLAGS) -- ./main
	@echo -e "\n===  GNU MPFR 128-bit floating point  ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-mpfr.so     $(FLAGS) -- ./main

main: main.c
	gcc -g -O1 -I$(TOOL_PATH) -o main main.c $(TOOL_PATH)/obj-intel64/shvalrt.a

clean:
	rm -f main *.log

