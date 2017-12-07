

# 可执行文件
TARGET=createTcp
# C文件
SRCS = makeTcpConnection.c
# 目标文件
OBJS = $(SRCS:.c=.o)

# 指令编译器和选项
CC=gcc
CFLAGS=-Wall -std=gnu99 -g
LDFLAGS=-lpcap -lnet -lpthread

$(TARGET):$(OBJS)
#   @echo TARGET:$@
#   @echo OBJECTS:$^
	$(CC) -o $@ $^ ${LDFLAGS}

clean:
	rm -rf $(TARGET) $(OBJS)

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<