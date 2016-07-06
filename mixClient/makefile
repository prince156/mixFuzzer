CFLAG= -std=c++11 -D__LINUX__

mixClient: common.o glogger.o mixClient.o
	@g++ $(CFLAG) common.o glogger.o mixClient.o -o mixClient

common.o: common.cpp
	@g++ $(CFLAG) -c common.cpp

glogger.o: glogger.cpp
	@g++ $(CFLAG) -c glogger.cpp

mixClient.o: mixClient.cpp
	@g++ $(CFLAG) -c mixClient.cpp
