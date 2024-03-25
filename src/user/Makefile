CC=gcc
CFLAGS := -I../../includes -I../../libbpf/src/root/usr/include -L../../libbpf/src -g
OBJECT_LIBBPF = ../../libbpf/src/libbpf.a
LIBS= -lbpf -lelf -lz

.PHONY: dpi_agent

dpi_agent: bpf_dpi_user.c $(OBJECT_LIBBPF)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
