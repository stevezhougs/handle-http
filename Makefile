CC = gcc
CPP = g++

INC=-I./ -I/usr/local/lib
LIBS= -lhtp -lpthread -lev -L/lib64/
CFLAG     =  -g3 -c -rdynamic -Werror-implicit-function-declaration -Wall -DZSHOW_LOG -DDEBUG
CPPFLAGS  =  -g3 -c -rdynamic -Wall

OBJS = socks5.o util.o log.o detect-http.o app-layer-htp-body.o app-layer-htp-libhtp.o util-file.o util-spm-bs2bm.o util-spm.o util-hash.o

TARGET=detect-http
#%.o:%.cpp
	#$(CPP) $(CPPFLAGS) $< -o $@
%.o:%.c
	$(CC) $(CFLAG) $< -o $@

$(TARGET):$(OBJS)
	$(CPP) -g3 -o $(TARGET) $(OBJS) $(LIBS)
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(OBJS) $(TARGET)
