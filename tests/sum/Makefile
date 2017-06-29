# PIN_ROOT should point to Pin installation
#export PIN_ROOT=$(HOME)/opt/pin-2.14-71313-gcc.4.4.7-linux

TOOL_PATH=../../tools

PIN=$(PIN_ROOT)/pin
FLAGS=-s -q

default: main

run: main
	@rm -f *.log
	@echo -e "\n===  Native 32-bit floating point  ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-native32.so $(FLAGS) -- ./main
	@echo -e "\n===  Native 64-bit floating point  ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-native64.so $(FLAGS) -- ./main
	@echo -e "\n===  Dataflow tracing ==="
	@$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-trace.so    $(FLAGS) -- ./main
	@dot -Tpng -o trace.png trace.dot
	@#
	@# UNCOMMENT THE FOLLOWING LINES TO RUN RANGE TRACKING TEST (Pin 2.14 only)
	@#
	@#echo -e "\n===  Range tracking  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-range.so    $(FLAGS) -- ./main
	@#
	@# UNCOMMENT THE FOLLOWING LINES TO RUN MPFR TEST (Pin 2.14 only)
	@#
	@#echo -e "\n===  GNU MPFR 10-bit floating point  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-mpfr.so -bits 10 $(FLAGS) -- ./main
	@#echo -e "\n===  GNU MPFR 113-bit floating point  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-mpfr.so -bits 113 $(FLAGS) -- ./main
	@#
	@# UNCOMMENT THE FOLLOWING LINES TO RUN NATIVE80 TEST (Pin 3.2 only)
	@#
	@#echo -e "\n===  Native 80-bit floating point  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-native80.so $(FLAGS) -- ./main
	@#
	@# UNCOMMENT THE FOLLOWING LINES TO RUN UNUM TESTS (library required)
	@#
	@#echo -e "\n===  Unums w/ (3,2) environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-unum.so $(FLAGS) -ess 3 -fss 2 -- ./main
	@#echo -e "\n===  Unums w/ (3,4) environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-unum.so $(FLAGS) -ess 3 -fss 4 -- ./main
	@#echo -e "\n===  Unums w/ (4,6) environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-unum.so $(FLAGS) -ess 4 -fss 6 -- ./main
	@#
	@# UNCOMMENT THE FOLLOWING LINES TO RUN POSIT TESTS (library required)
	@#
	@#echo -e "\n===  8-bit Posits w/ es=0 environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-posit8e0.so $(FLAGS)  -- ./main
	@#echo -e "\n===  16-bit Posits w/ es=1 environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-posit16e1.so $(FLAGS) -- ./main
	@#echo -e "\n===  16-bit Posits w/ es=2 environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-posit16e2.so $(FLAGS) -- ./main
	@#echo -e "\n===  32-bit Posits w/ es=3 environment  ==="
	@#$(PIN) -t $(TOOL_PATH)/obj-intel64/shval-posit32e3.so $(FLAGS) -- ./main

main: main.c
	gcc -g -Og -I$(TOOL_PATH) -o main main.c $(TOOL_PATH)/obj-intel64/shvalrt.a

clean:
	rm -f main *.log *.dot *.png

