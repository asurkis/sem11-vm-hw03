all: main.exe

run: all
	./main.exe

main.exe: main.o
	$(CXX) -o $@ $^ 

clean:
	rm -f *.o *.exe
