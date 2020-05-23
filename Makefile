JAVA_HOME = /usr/lib/jvm/java-11-openjdk-amd64

CPPFLAGS = -DLIBBSD_OVERLAY -isystem /usr/include/bsd \
           -I"$(JAVA_HOME)/include" \
           -I"$(JAVA_HOME)/include/linux"
CFLAGS = -fvisibility=hidden -fPIC -O3 -Wall
LDFLAGS = -shared -s

objects = agent.o profiler.o
output = profiler-agent.so

$(output): $(objects)
	$(CC) -o $@ $(LDFLAGS) $^

clean:
	$(RM) -f $(objects) $(output)
