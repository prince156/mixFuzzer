CFLAG= -std=c++11 -D__LINUX__

mixClient: mixClient.o glogger.o common.o
	@g++ $(CFLAG) mixClient.o glogger.o common.o -o mixClient

common.o: common.cpp common.h tstream.h
	@g++ $(CFLAG) -c common.cpp

glogger.o: glogger.cpp glogger.h tstream.h
	@g++ $(CFLAG) -c glogger.cpp

mixClient.o: mixClient.cpp
	@g++ $(CFLAG) -c mixClient.cpp

.PHONY: clean
clean:
	rm -f *.o mixClient
