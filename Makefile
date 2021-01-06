client_linked.o: client.o iodine-src/iodine.o
	ld -r client.o iodine-src/iodine.o -o client_linked.o
server_linked.o: server.o iodine-src/iodined.o
	ld -r server.o iodine-src/iodined.o -o server_linked.o

.PHONY: iodine-src/iodine.o iodine-src/iodined.o
iodine-src/iodine.o:
	cd iodine-src; $(MAKE) TARGETOS=$(TARGETOS) iodine.o
iodine-src/iodined.o:
	cd iodine-src; $(MAKE) TARGETOS=$(TARGETOS) iodined.o