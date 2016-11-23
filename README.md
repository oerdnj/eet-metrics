Jednoduchý měřák pro EET
========================

Jednoduchá binárka na měření různých částí komunikace se systémem EET
přes IPv4 i IPv6.  Validně podepsané SOAP zprávy musí dodat uživatel.

Není to moc odolné, a pokud v nějakém kroku nastane chyba, tak celé
měření selže.  Patche (MR) na vylepšení jsou vítány.

Kompilace
---------

Vyžaduje POSIXový systém (a asi i Linux) a GnuTLS > 3.1.5

Spuštěním make se vygeneruje binárka `eet-metrics`.

Spuštění
--------

./eet-metrics bez parametrů - vypíše hlavičku CSV:
```
$ ./eet-metrics 
    getaddrinfo,       connect4, tls_handshake4,      tls_send4,      tls_recv4,       tls_bye4,         close4,       connect6, tls_handshake6,      tls_send6,      tls_recv6,       tls_bye6,         close6
```
./eet-metrics s parametry: <host> <port> <ipv4_xml> <ipv6_xml> vypíše změřené hodnoty (sec.usec)
```
./eet-metrics pg.eet.cz 443 CZ1212121218.valid.v3.1.xml CZ1212121218.valid.v3.1.xml
   0.0000659542,   0.0002460621,   0.0062778838,   0.0000035884,   0.0013765012,   0.0005423515,   0.0000076422,   0.0005387902,   0.0076648387,   0.0000072605,   0.0015461622,   0.0002251310,   0.0000074908
```
