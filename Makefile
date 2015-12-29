###########################################
#Makefile for simple programs
###########################################
INC=-I./ -I/usr/local/lib
LIB=-lhtp

CC=gcc
CFLAG=-g3 -rdynamic -Werror-implicit-function-declaration -Wall -DZSHOW_LOG -DDEBUG -DZSHOWENTER -DZPRINT


PRG=detect-http
OBJ=util.o log.o main.o detect-http.o app-layer-htp-body.o util-file.o util-spm-bs2bm.o util-spm.o

$(PRG):$(OBJ)
	$(CC) $(INC) $(LIB) -o $@ $(OBJ)
	
.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAG) $(INC) -c $*.c -o $*.o

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(OBJ) $(PRG)
