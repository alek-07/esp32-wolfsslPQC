#pragma once

/* 
embedded version of CERT_FILE

example to generate this CERT_FILE text for a new file:

sed 's/\(.*\)\r/"\1\\n"/g' client-cert.pem

see also this DER to C script:

https://github.com/wolfSSL/wolfssl/blob/master/scripts/dertoc.pl

*/

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
const unsigned char * CERT_FILE = ""
    
/* TODO this is a test example! DO NOT USE IN PRODUCTION!! */

/* insert your client-cert.pem text below */ 
"Certificate:\n"
"    Data:\n"
"        Version: 3 (0x2)\n"
"        Serial Number:\n"
"            4f:0d:8c:c5:fa:ee:a2:9b:b7:35:9e:e9:4a:17:99:f0:cc:23:f2:ec\n"
"        Signature Algorithm: sha256WithRSAEncryption\n"
"        Issuer: C = US, ST = Montana, L = Bozeman, O = wolfSSL_2048, OU = Programming-2048, CN = www.wolfssl.com, emailAddress = info@wolfssl.com\n"
"        Validity\n"
"            Not Before: Dec 18 21:25:29 2024 GMT\n"
"            Not After : Sep 14 21:25:29 2027 GMT\n"
"        Subject: C = US, ST = Montana, L = Bozeman, O = wolfSSL_2048, OU = Programming-2048, CN = www.wolfssl.com, emailAddress = info@wolfssl.com\n"
"        Subject Public Key Info:\n"
"            Public Key Algorithm: rsaEncryption\n"
"                Public-Key: (2048 bit)\n"
"                Modulus:\n"
"                    00:c3:03:d1:2b:fe:39:a4:32:45:3b:53:c8:84:2b:\n"
"                    2a:7c:74:9a:bd:aa:2a:52:07:47:d6:a6:36:b2:07:\n"
"                    32:8e:d0:ba:69:7b:c6:c3:44:9e:d4:81:48:fd:2d:\n"
"                    68:a2:8b:67:bb:a1:75:c8:36:2c:4a:d2:1b:f7:8b:\n"
"                    ba:cf:0d:f9:ef:ec:f1:81:1e:7b:9b:03:47:9a:bf:\n"
"                    65:cc:7f:65:24:69:a6:e8:14:89:5b:e4:34:f7:c5:\n"
"                    b0:14:93:f5:67:7b:3a:7a:78:e1:01:56:56:91:a6:\n"
"                    13:42:8d:d2:3c:40:9c:4c:ef:d1:86:df:37:51:1b:\n"
"                    0c:a1:3b:f5:f1:a3:4a:35:e4:e1:ce:96:df:1b:7e:\n"
"                    bf:4e:97:d0:10:e8:a8:08:30:81:af:20:0b:43:14:\n"
"                    c5:74:67:b4:32:82:6f:8d:86:c2:88:40:99:36:83:\n"
"                    ba:1e:40:72:22:17:d7:52:65:24:73:b0:ce:ef:19:\n"
"                    cd:ae:ff:78:6c:7b:c0:12:03:d4:4e:72:0d:50:6d:\n"
"                    3b:a3:3b:a3:99:5e:9d:c8:d9:0c:85:b3:d9:8a:d9:\n"
"                    54:26:db:6d:fa:ac:bb:ff:25:4c:c4:d1:79:f4:71:\n"
"                    d3:86:40:18:13:b0:63:b5:72:4e:30:c4:97:84:86:\n"
"                    2d:56:2f:d7:15:f7:7f:c0:ae:f5:fc:5b:e5:fb:a1:\n"
"                    ba:d3\n"
"                Exponent: 65537 (0x10001)\n"
"        X509v3 extensions:\n"
"            X509v3 Subject Key Identifier: \n"
"                33:D8:45:66:D7:68:87:18:7E:54:0D:70:27:91:C7:26:D7:85:65:C0\n"
"            X509v3 Authority Key Identifier: \n"
"                keyid:33:D8:45:66:D7:68:87:18:7E:54:0D:70:27:91:C7:26:D7:85:65:C0\n"
"                DirName:/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n"
"                serial:4F:0D:8C:C5:FA:EE:A2:9B:B7:35:9E:E9:4A:17:99:F0:CC:23:F2:EC\n"
"            X509v3 Basic Constraints: \n"
"                CA:TRUE\n"
"            X509v3 Subject Alternative Name: \n"
"                DNS:example.com, IP Address:127.0.0.1\n"
"            X509v3 Extended Key Usage: \n"
"                TLS Web Server Authentication, TLS Web Client Authentication\n"
"    Signature Algorithm: sha256WithRSAEncryption\n"
"    Signature Value:\n"
"        46:ab:e4:6d:ae:49:5b:6a:0b:a9:87:e1:95:32:a6:d7:ae:de:\n"
"        28:dc:c7:99:68:e2:5f:c9:5a:4c:64:b8:f5:28:42:5a:e8:5c:\n"
"        59:32:fe:d0:1f:0b:55:89:db:67:e7:78:f3:70:cf:18:51:57:\n"
"        8b:f3:2b:a4:66:0b:f6:03:6e:11:ac:83:52:16:7e:a2:7c:36:\n"
"        77:f6:bb:13:19:40:2c:b8:8c:ca:d6:7e:79:7d:f4:14:8d:b5:\n"
"        a4:09:f6:2d:4c:e7:f9:b8:25:41:15:78:f4:ca:80:41:ea:3a:\n"
"        05:08:f6:b5:5b:a1:3b:5b:48:a8:4b:8c:19:8d:6c:87:31:76:\n"
"        74:02:16:8b:dd:7f:d1:11:62:27:42:39:e0:9a:63:26:31:19:\n"
"        ce:3d:41:d5:24:47:32:0f:76:d6:41:37:44:ad:73:f1:b8:ec:\n"
"        2b:6e:9c:4f:84:c4:4e:d7:92:10:7e:23:32:a0:75:6a:e7:fe:\n"
"        55:95:9f:0a:ad:df:f9:2a:a2:1a:59:d5:82:63:d6:5d:7d:79:\n"
"        f4:a7:2d:dc:8c:04:cd:98:b0:42:0e:84:fa:86:50:10:61:ac:\n"
"        73:cd:79:45:30:e8:42:a1:6a:f6:77:55:ec:07:db:52:29:ca:\n"
"        7a:c8:a2:da:e9:f5:98:33:6a:e8:bc:89:ed:01:e2:fe:44:86:\n"
"        86:80:39:ec\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIFHTCCBAWgAwIBAgIUTw2Mxfruopu3NZ7pSheZ8Mwj8uwwDQYJKoZIhvcNAQEL\n"
"BQAwgZ4xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMRAwDgYDVQQHDAdC\n"
"b3plbWFuMRUwEwYDVQQKDAx3b2xmU1NMXzIwNDgxGTAXBgNVBAsMEFByb2dyYW1t\n"
"aW5nLTIwNDgxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3DQEJ\n"
"ARYQaW5mb0B3b2xmc3NsLmNvbTAeFw0yNDEyMTgyMTI1MjlaFw0yNzA5MTQyMTI1\n"
"MjlaMIGeMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwH\n"
"Qm96ZW1hbjEVMBMGA1UECgwMd29sZlNTTF8yMDQ4MRkwFwYDVQQLDBBQcm9ncmFt\n"
"bWluZy0yMDQ4MRgwFgYDVQQDDA93d3cud29sZnNzbC5jb20xHzAdBgkqhkiG9w0B\n"
"CQEWEGluZm9Ad29sZnNzbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
"AoIBAQDDA9Er/jmkMkU7U8iEKyp8dJq9qipSB0fWpjayBzKO0Lppe8bDRJ7UgUj9\n"
"LWiii2e7oXXINixK0hv3i7rPDfnv7PGBHnubA0eav2XMf2UkaaboFIlb5DT3xbAU\n"
"k/Vnezp6eOEBVlaRphNCjdI8QJxM79GG3zdRGwyhO/Xxo0o15OHOlt8bfr9Ol9AQ\n"
"6KgIMIGvIAtDFMV0Z7Qygm+NhsKIQJk2g7oeQHIiF9dSZSRzsM7vGc2u/3hse8AS\n"
"A9ROcg1QbTujO6OZXp3I2QyFs9mK2VQm2236rLv/JUzE0Xn0cdOGQBgTsGO1ck4w\n"
"xJeEhi1WL9cV93/ArvX8W+X7obrTAgMBAAGjggFPMIIBSzAdBgNVHQ4EFgQUM9hF\n"
"Ztdohxh+VA1wJ5HHJteFZcAwgd4GA1UdIwSB1jCB04AUM9hFZtdohxh+VA1wJ5HH\n"
"JteFZcChgaSkgaEwgZ4xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMRAw\n"
"DgYDVQQHDAdCb3plbWFuMRUwEwYDVQQKDAx3b2xmU1NMXzIwNDgxGTAXBgNVBAsM\n"
"EFByb2dyYW1taW5nLTIwNDgxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0G\n"
"CSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbYIUTw2Mxfruopu3NZ7pSheZ8Mwj\n"
"8uwwDAYDVR0TBAUwAwEB/zAcBgNVHREEFTATggtleGFtcGxlLmNvbYcEfwAAATAd\n"
"BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEB\n"
"AEar5G2uSVtqC6mH4ZUypteu3ijcx5lo4l/JWkxkuPUoQlroXFky/tAfC1WJ22fn\n"
"ePNwzxhRV4vzK6RmC/YDbhGsg1IWfqJ8Nnf2uxMZQCy4jMrWfnl99BSNtaQJ9i1M\n"
"5/m4JUEVePTKgEHqOgUI9rVboTtbSKhLjBmNbIcxdnQCFovdf9ERYidCOeCaYyYx\n"
"Gc49QdUkRzIPdtZBN0Stc/G47CtunE+ExE7XkhB+IzKgdWrn/lWVnwqt3/kqohpZ\n"
"1YJj1l19efSnLdyMBM2YsEIOhPqGUBBhrHPNeUUw6EKhavZ3VewH21IpynrIotrp\n"
"9Zgzaui8ie0B4v5EhoaAOew=\n"
"-----END CERTIFICATE-----\n"
/* insert your client-cert.pem text above */    
"\x00"
;
long sizeof_CERT_FILE() {
    unsigned char * p;
    p = strchr(CERT_FILE, 0);
    return p - CERT_FILE + 1;
};

#pragma GCC diagnostic pop



