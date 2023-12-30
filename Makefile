all: main.exe

run: all
	./main.exe ./Sort.bc

main.exe: main.o
	$(CXX) -o $@ $^ 

clean:
	rm -f *.o *.exe
