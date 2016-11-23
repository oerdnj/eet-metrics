all: eet-metrics

eet-metrics: eet-metrics.c
	$(CC) eet-metrics.c -o eet-metrics -lgnutls
