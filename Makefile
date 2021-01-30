
LIBS+= -lssl -lcrypto

OBJS= sslTools.o
OBJS1= sslTunnel.o
OBJS2= sslConnect.o

all: sslTunnel sslConnect

sslTunnel: $(OBJS) $(OBJS1)
	$(CC) $(CFLAGS) $(LDFLAGS) $? -o $@ $(LIBS)

sslConnect: $(OBJS) $(OBJS2)
	$(CC) $(CFLAGS) $(LDFLAGS) $? -o $@ $(LIBS)

clean:
	rm -f *.o sslTunnel sslConnect



