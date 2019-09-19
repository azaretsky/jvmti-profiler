OBJECTS = agent.o profiler.o
OUTPUT = profiler-agent.so

LDFLAGS = -shared -s
CFLAGS = -fvisibility=hidden -fPIC -O3 -Wall
CPPFLAGS = -DLIBBSD_OVERLAY -isystem /usr/include/bsd \
           -I/usr/lib/jvm/java-8-openjdk-amd64/include \
           -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux

$(OUTPUT): $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) $^

clean:
	$(RM) -f $(OBJECTS) $(OUTPUT)
