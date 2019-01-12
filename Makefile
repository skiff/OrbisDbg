all:
	+$(MAKE) -C ELF clean
	+$(MAKE) -C ELF
	+$(MAKE) -C Payload clean
	+$(MAKE) -C Payload

	objcopy -O binary Payload/OrbisDbg.bin OrbisDbg.bin