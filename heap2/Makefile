CC=gcc
CFLAGS=-m32 -fstack-protector
TARGET=heap
SRC=heap.c

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm $(TARGET)

