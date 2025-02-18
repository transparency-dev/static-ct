// Copyright 2016 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testdata

// This file holds test certificates. It contain four independent issuance
// chains.
// TODO(phboneff): clean this and make use of a single chain if possible.
// TODO(phboneff): Use PRIVATE TESTING KEY instated of PRIVATE KEY.

// Issuance chain 1
// ================
// The next section holds a self signed root, a leaf cert and a precert
// issued from it directly.

// CACertPEM is a valid test CA certificate.
// Data:
//     Version: 3 (0x2)
//     Serial Number: 1 (0x1)
//     Signature Algorithm: sha256WithRSAEncryption
//     Issuer: C=GB, O=TrustFabric Transparency.dev Test Root Test CA, CN=TrustFabric Transparency.dev Test Root Test CA
//     Validity
//         Not Before: Feb 18 16:59:02 2025 GMT
//         Not After : Feb 18 16:59:02 2035 GMT
//     Subject: C=GB, O=TrustFabric Transparency.dev Test Root Test CA, CN=TrustFabric Transparency.dev Test Root Test CA
//     Subject Public Key Info:
//         Public Key Algorithm: rsaEncryption
//             Public-Key: (2048 bit)
//             Modulus:
//                 00:d6:c3:06:a7:a5:3b:96:15:24:d9:04:dc:9c:d6:
//                 79:e3:cb:d2:6d:dc:99:b8:c7:d4:2d:40:9f:37:07:
//                 b2:af:32:67:b9:72:0d:dd:72:ea:c6:a1:da:34:21:
//                 22:38:5a:e1:17:b4:2e:10:84:f8:3e:be:71:d8:78:
//                 37:9c:83:24:c6:78:71:47:77:71:29:8f:07:f1:ef:
//                 a0:4c:d2:de:56:e7:53:78:9c:b4:6b:bd:07:e4:a8:
//                 99:ae:27:fb:ab:7d:4b:e0:2a:f6:10:44:49:1c:b6:
//                 6f:83:2a:2f:c5:32:93:10:87:18:63:67:0d:6a:8f:
//                 a6:19:e7:3b:ca:34:9a:be:43:db:56:56:8c:40:8d:
//                 5f:12:0d:14:d5:68:06:83:8b:dc:da:f4:de:76:15:
//                 0f:23:c3:c3:03:84:33:d5:9f:fe:41:2a:c7:80:ca:
//                 af:59:e3:2e:fe:f7:8e:bf:2c:f1:91:c0:1d:56:5e:
//                 ec:2b:02:d5:8b:c9:27:c7:07:70:59:0a:7b:b9:29:
//                 ea:22:fa:9f:50:dc:51:7d:11:19:1c:8f:7d:9c:93:
//                 26:a4:16:79:90:41:9e:f0:1f:17:35:5e:d8:48:95:
//                 e5:09:de:d6:9b:52:f9:9f:2e:02:e6:be:c8:42:38:
//                 7c:4d:dd:9f:3f:89:20:29:aa:b9:5c:34:fa:bc:44:
//                 58:2d
//             Exponent: 65537 (0x10001)
//     X509v3 extensions:
//         X509v3 Key Usage: critical
//             Certificate Sign, CRL Sign
//         X509v3 Basic Constraints: critical
//             CA:TRUE
//         X509v3 Subject Key Identifier:
//             2C:3F:8C:DC:E4:71:9D:D2:57:7F:25:C8:7C:FA:3F:9B:1C:67:A4:F0
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//     b7:83:0d:d2:50:44:ec:32:17:cb:19:f6:f8:f0:ff:b6:37:80:
//     b6:ee:ca:2f:9e:7a:d4:6d:59:92:a1:02:5b:9a:63:0f:88:0b:
//     9c:94:1d:87:a2:4a:e7:9e:99:f7:2a:a7:99:d8:95:bd:08:2b:
//     ea:28:6b:e3:35:e5:2f:89:51:91:e7:f1:99:2a:b4:02:79:61:
//     cf:7d:9a:79:0d:16:14:1c:58:05:e2:9c:3c:77:9d:22:3d:76:
//     00:55:a8:77:14:ed:79:b7:37:eb:0c:29:7f:4d:e9:4e:23:62:
//     47:cb:7b:28:fe:63:a4:67:8c:d3:84:1e:33:50:72:64:75:4b:
//     4c:0f:83:23:d3:27:fb:72:b7:e6:fe:60:84:e3:5b:96:20:af:
//     ca:77:05:ac:ca:9e:06:fa:fc:5f:ae:9e:26:ba:d1:1e:e6:70:
//     04:07:4b:f4:3f:61:8e:3a:51:e2:27:12:b2:53:c3:3c:33:7c:
//     cf:0e:9e:a8:fd:b5:e7:a1:60:9d:89:27:d7:c3:a1:f2:c2:64:
//     04:3f:cf:ef:4e:77:ef:0e:b0:3e:b8:24:db:63:45:61:ab:2a:
//     af:1d:b4:75:ae:99:23:64:2e:4c:8b:b4:6d:18:fa:37:08:28:
//     e5:d8:8a:83:36:ac:af:28:3f:c8:16:8b:fd:3e:fc:1d:37:ab:
//     ad:51:22:40

const CACertPEM = `
-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIBATANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJHQjE3
MDUGA1UEChMuVHJ1c3RGYWJyaWMgVHJhbnNwYXJlbmN5LmRldiBUZXN0IFJvb3Qg
VGVzdCBDQTE3MDUGA1UEAxMuVHJ1c3RGYWJyaWMgVHJhbnNwYXJlbmN5LmRldiBU
ZXN0IFJvb3QgVGVzdCBDQTAeFw0yNTAyMTgxNjU5MDJaFw0zNTAyMTgxNjU5MDJa
MH8xCzAJBgNVBAYTAkdCMTcwNQYDVQQKEy5UcnVzdEZhYnJpYyBUcmFuc3BhcmVu
Y3kuZGV2IFRlc3QgUm9vdCBUZXN0IENBMTcwNQYDVQQDEy5UcnVzdEZhYnJpYyBU
cmFuc3BhcmVuY3kuZGV2IFRlc3QgUm9vdCBUZXN0IENBMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA1sMGp6U7lhUk2QTcnNZ548vSbdyZuMfULUCfNwey
rzJnuXIN3XLqxqHaNCEiOFrhF7QuEIT4Pr5x2Hg3nIMkxnhxR3dxKY8H8e+gTNLe
VudTeJy0a70H5KiZrif7q31L4Cr2EERJHLZvgyovxTKTEIcYY2cNao+mGec7yjSa
vkPbVlaMQI1fEg0U1WgGg4vc2vTedhUPI8PDA4Qz1Z/+QSrHgMqvWeMu/veOvyzx
kcAdVl7sKwLVi8knxwdwWQp7uSnqIvqfUNxRfREZHI99nJMmpBZ5kEGe8B8XNV7Y
SJXlCd7Wm1L5ny4C5r7IQjh8Td2fP4kgKaq5XDT6vERYLQIDAQABo0IwQDAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQULD+M3ORxndJX
fyXIfPo/mxxnpPAwDQYJKoZIhvcNAQELBQADggEBALeDDdJQROwyF8sZ9vjw/7Y3
gLbuyi+eetRtWZKhAluaYw+IC5yUHYeiSueemfcqp5nYlb0IK+ooa+M15S+JUZHn
8ZkqtAJ5Yc99mnkNFhQcWAXinDx3nSI9dgBVqHcU7Xm3N+sMKX9N6U4jYkfLeyj+
Y6RnjNOEHjNQcmR1S0wPgyPTJ/tyt+b+YITjW5Ygr8p3BazKngb6/F+unia60R7m
cAQHS/Q/YY46UeInErJTwzwzfM8Onqj9teehYJ2JJ9fDofLCZAQ/z+9Od+8OsD64
JNtjRWGrKq8dtHWumSNkLkyLtG0Y+jcIKOXYioM2rK8oP8gWi/0+/B03q61RIkA=
-----END CERTIFICATE-----`

// PrecertPEMValid is a test certificate containing a valid CT precertificate
// extension.
// Data:
//     Version: 3 (0x2)
//     Serial Number: 200 (0xc8)
//     Signature Algorithm: sha256WithRSAEncryption
//     Issuer: C=GB, O=TrustFabric Transparency.dev Test Root Test CA, CN=TrustFabric Transparency.dev Test Root Test CA
//     Validity
//         Not Before: Jan  1 00:00:00 2023 GMT
//         Not After : Jan  1 00:00:00 2024 GMT
//     Subject: C=GB, ST=London, L=London, O=TrustFabric Transparency.dev Test, OU=TrustFabric, CN=test.transparency.dev
//     Subject Public Key Info:
//         Public Key Algorithm: rsaEncryption
//             Public-Key: (2048 bit)
//             Modulus:
//                 00:b9:d2:c7:c2:15:9c:f7:ea:45:fd:d4:2b:ed:e9:
//                 60:cb:0e:68:75:c8:16:f2:c0:12:63:75:52:d2:f6:
//                 24:2a:1d:76:99:16:f6:02:c2:1a:5a:d0:20:fe:07:
//                 3a:9a:79:bf:72:d8:ea:8e:6e:49:69:dc:b9:0c:b9:
//                 45:16:cc:33:bf:29:f9:88:52:48:0a:b8:e9:44:ff:
//                 c4:9c:c4:23:a3:ab:ec:27:cf:7c:ce:72:26:b2:14:
//                 43:b9:a3:0b:d6:00:f7:36:13:62:01:b1:65:24:88:
//                 e5:3e:f7:8c:15:07:65:79:74:c3:ce:02:75:39:ed:
//                 1c:43:cf:47:69:b8:7d:22:1e:f4:d4:37:4d:8d:12:
//                 5c:57:8d:48:61:fb:8b:0e:56:b4:8b:7a:f1:30:16:
//                 54:4b:96:8b:13:34:3a:b6:99:2d:d4:b3:f4:df:85:
//                 a9:c5:d2:19:06:5b:40:7e:d0:f7:28:a4:bd:cc:11:
//                 ae:5c:e3:74:a0:1d:be:31:e4:cb:e4:a8:26:2a:ff:
//                 c1:92:c1:8d:ac:56:8c:84:fb:25:9a:83:e6:73:dd:
//                 ed:b4:70:2a:9f:52:d8:4f:36:09:37:ac:ad:ad:00:
//                 79:96:db:b7:b0:e4:5d:24:a9:bb:83:51:95:81:65:
//                 f6:0e:c1:23:d3:22:50:e8:81:4d:c5:ec:51:88:9d:
//                 4a:a1
//             Exponent: 65537 (0x10001)
//     X509v3 extensions:
//         X509v3 Key Usage: critical
//             Digital Signature, Key Encipherment
//         X509v3 Extended Key Usage:
//             TLS Web Server Authentication
//         X509v3 Basic Constraints: critical
//             CA:FALSE
//         X509v3 Authority Key Identifier:
//             2C:3F:8C:DC:E4:71:9D:D2:57:7F:25:C8:7C:FA:3F:9B:1C:67:A4:F0
//         X509v3 Subject Alternative Name:
//             DNS:test.transparency.dev
//         CT Precertificate Poison: critical
//             NULL
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//     18:51:44:ad:9a:bd:96:19:49:77:a9:33:e0:d8:9f:20:fa:e0:
//     00:83:75:95:e7:39:f9:7a:62:b0:1d:81:61:a5:df:c4:d4:a5:
//     69:4a:0a:b5:44:e1:04:9a:b5:cb:86:0b:ad:f8:9c:0b:11:20:
//     f9:90:0b:70:5f:e6:29:45:cc:b8:fe:0d:4e:fe:bd:7c:98:33:
//     04:84:c1:0b:8c:4e:9a:f4:09:6d:1f:5d:4e:1d:d0:b6:62:c7:
//     01:56:f2:96:a0:30:4a:22:07:ad:a2:ef:48:2f:f6:a9:82:68:
//     a6:4c:df:9b:32:dc:d0:37:a3:22:82:3b:13:f5:c6:c3:f0:d2:
//     a8:75:b9:5e:93:bf:e2:a6:91:d4:41:3f:91:c8:31:23:3e:5c:
//     76:58:1c:59:5d:46:d4:a6:eb:b6:77:57:f0:3a:79:f3:67:94:
//     27:1f:6a:63:cc:b1:dd:20:3e:dd:e5:a9:a2:fe:c1:61:a3:da:
//     7d:ae:5d:62:b9:d5:18:7a:2c:89:a7:63:4e:f3:f1:56:c8:f3:
//     3a:e7:06:3d:62:25:90:cd:9f:80:08:31:93:f5:fe:3e:2f:2e:
//     5a:f5:06:3d:5d:d2:1b:f0:29:8f:40:e0:20:eb:7e:02:ae:8c:
//     d7:09:31:68:f9:b1:1e:ba:84:9f:b0:7c:53:3c:7a:4c:41:f4:
//     d4:39:6c:68

const PrecertPEMValid = `
-----BEGIN CERTIFICATE-----
MIIEHDCCAwSgAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwfzELMAkGA1UEBhMCR0Ix
NzA1BgNVBAoTLlRydXN0RmFicmljIFRyYW5zcGFyZW5jeS5kZXYgVGVzdCBSb290
IFRlc3QgQ0ExNzA1BgNVBAMTLlRydXN0RmFicmljIFRyYW5zcGFyZW5jeS5kZXYg
VGVzdCBSb290IFRlc3QgQ0EwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAw
WjCBkTELMAkGA1UEBhMCR0IxDzANBgNVBAgTBkxvbmRvbjEPMA0GA1UEBxMGTG9u
ZG9uMSowKAYDVQQKEyFUcnVzdEZhYnJpYyBUcmFuc3BhcmVuY3kuZGV2IFRlc3Qx
FDASBgNVBAsTC1RydXN0RmFicmljMR4wHAYDVQQDExV0ZXN0LnRyYW5zcGFyZW5j
eS5kZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC50sfCFZz36kX9
1Cvt6WDLDmh1yBbywBJjdVLS9iQqHXaZFvYCwhpa0CD+Bzqaeb9y2OqObklp3LkM
uUUWzDO/KfmIUkgKuOlE/8ScxCOjq+wnz3zOciayFEO5owvWAPc2E2IBsWUkiOU+
94wVB2V5dMPOAnU57RxDz0dpuH0iHvTUN02NElxXjUhh+4sOVrSLevEwFlRLlosT
NDq2mS3Us/TfhanF0hkGW0B+0PcopL3MEa5c43SgHb4x5MvkqCYq/8GSwY2sVoyE
+yWag+Zz3e20cCqfUthPNgk3rK2tAHmW27ew5F0kqbuDUZWBZfYOwSPTIlDogU3F
7FGInUqhAgMBAAGjgY4wgYswDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAULD+M3ORxndJXfyXIfPo/
mxxnpPAwIAYDVR0RBBkwF4IVdGVzdC50cmFuc3BhcmVuY3kuZGV2MBMGCisGAQQB
1nkCBAMBAf8EAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAYUUStmr2WGUl3qTPg2J8g
+uAAg3WV5zn5emKwHYFhpd/E1KVpSgq1ROEEmrXLhgut+JwLESD5kAtwX+YpRcy4
/g1O/r18mDMEhMELjE6a9AltH11OHdC2YscBVvKWoDBKIgetou9IL/apgmimTN+b
MtzQN6MigjsT9cbD8NKodblek7/ippHUQT+RyDEjPlx2WBxZXUbUpuu2d1fwOnnz
Z5QnH2pjzLHdID7d5ami/sFho9p9rl1iudUYeiyJp2NO8/FWyPM65wY9YiWQzZ+A
CDGT9f4+Ly5a9QY9XdIb8CmPQOAg634CrozXCTFo+bEeuoSfsHxTPHpMQfTUOWxo
-----END CERTIFICATE-----`

// TestCertPEM is a certificate issued by CACertPEM, no CT extensions.
// Data:
//
//	Version: 3 (0x2)
//	Serial Number: 100 (0x64)
//	Signature Algorithm: sha256WithRSAEncryption
//	Issuer: C=GB, O=TrustFabric Transparency.dev Test Root Test CA, CN=TrustFabric Transparency.dev Test Root Test CA
//	Validity
//	    Not Before: Jan  1 00:00:00 2023 GMT
//	    Not After : Jan  1 00:00:00 2024 GMT
//	Subject: C=GB, ST=London, L=London, O=TrustFabric Transparency.dev Test, OU=TrustFabric, CN=test.transparency.dev
//	Subject Public Key Info:
//	    Public Key Algorithm: rsaEncryption
//	        Public-Key: (2048 bit)
//	        Modulus:
//	            00:b9:d2:c7:c2:15:9c:f7:ea:45:fd:d4:2b:ed:e9:
//	            60:cb:0e:68:75:c8:16:f2:c0:12:63:75:52:d2:f6:
//	            24:2a:1d:76:99:16:f6:02:c2:1a:5a:d0:20:fe:07:
//	            3a:9a:79:bf:72:d8:ea:8e:6e:49:69:dc:b9:0c:b9:
//	            45:16:cc:33:bf:29:f9:88:52:48:0a:b8:e9:44:ff:
//	            c4:9c:c4:23:a3:ab:ec:27:cf:7c:ce:72:26:b2:14:
//	            43:b9:a3:0b:d6:00:f7:36:13:62:01:b1:65:24:88:
//	            e5:3e:f7:8c:15:07:65:79:74:c3:ce:02:75:39:ed:
//	            1c:43:cf:47:69:b8:7d:22:1e:f4:d4:37:4d:8d:12:
//	            5c:57:8d:48:61:fb:8b:0e:56:b4:8b:7a:f1:30:16:
//	            54:4b:96:8b:13:34:3a:b6:99:2d:d4:b3:f4:df:85:
//	            a9:c5:d2:19:06:5b:40:7e:d0:f7:28:a4:bd:cc:11:
//	            ae:5c:e3:74:a0:1d:be:31:e4:cb:e4:a8:26:2a:ff:
//	            c1:92:c1:8d:ac:56:8c:84:fb:25:9a:83:e6:73:dd:
//	            ed:b4:70:2a:9f:52:d8:4f:36:09:37:ac:ad:ad:00:
//	            79:96:db:b7:b0:e4:5d:24:a9:bb:83:51:95:81:65:
//	            f6:0e:c1:23:d3:22:50:e8:81:4d:c5:ec:51:88:9d:
//	            4a:a1
//	        Exponent: 65537 (0x10001)
//	X509v3 extensions:
//	    X509v3 Key Usage: critical
//	        Digital Signature, Key Encipherment
//	    X509v3 Extended Key Usage:
//	        TLS Web Server Authentication
//	    X509v3 Basic Constraints: critical
//	        CA:FALSE
//	    X509v3 Authority Key Identifier:
//	        2C:3F:8C:DC:E4:71:9D:D2:57:7F:25:C8:7C:FA:3F:9B:1C:67:A4:F0
//	    X509v3 Subject Alternative Name:
//	        DNS:test.transparency.dev
//	Signature Algorithm: sha256WithRSAEncryption
//	Signature Value:
//	b9:c2:b5:fa:44:82:3c:ca:fe:ea:f9:9a:73:00:47:20:87:f1:
//	43:c4:78:33:d3:49:32:db:81:aa:7a:87:4c:a1:00:31:97:cf:
//	82:d5:c1:54:d5:12:50:7e:f1:6d:3a:ae:86:99:5e:2f:e7:37:
//	9a:d2:68:e5:09:87:53:c2:43:72:6d:a8:d5:a5:7a:df:6b:cd:
//	7b:58:fc:d3:20:30:62:a8:3b:e4:27:b1:8f:f5:9e:e8:af:5e:
//	84:d0:9a:23:1f:72:18:39:b5:1e:61:54:94:da:cc:3c:85:69:
//	85:72:13:28:8f:b1:e2:9e:8b:22:1a:a6:3e:7a:b3:60:6c:96:
//	ac:b5:ca:5d:39:66:87:f6:0d:2f:32:ec:4e:80:e5:33:cb:ae:
//	29:52:1a:35:01:70:a3:d6:81:d0:1a:1e:c6:c3:ec:52:cc:20:
//	af:e0:c6:b9:ee:03:30:97:f0:26:b8:c8:24:15:a9:c3:67:e2:
//	c6:f7:83:3c:7f:50:16:e7:76:c6:f7:3a:f9:1c:ba:4e:f0:f7:
//	76:85:68:61:de:e5:2b:bc:c3:20:9b:6c:ff:44:1a:ad:f2:81:
//	8e:f2:39:36:4c:ea:e6:a0:81:4b:38:45:9c:55:cd:e6:09:29:
//	45:a3:51:51:71:ac:ab:77:e3:8d:03:37:a4:20:11:70:c9:2a:
//	32:49:25:a9
const TestCertPEM = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIBZDANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJHQjE3
MDUGA1UEChMuVHJ1c3RGYWJyaWMgVHJhbnNwYXJlbmN5LmRldiBUZXN0IFJvb3Qg
VGVzdCBDQTE3MDUGA1UEAxMuVHJ1c3RGYWJyaWMgVHJhbnNwYXJlbmN5LmRldiBU
ZXN0IFJvb3QgVGVzdCBDQTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBa
MIGRMQswCQYDVQQGEwJHQjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25k
b24xKjAoBgNVBAoTIVRydXN0RmFicmljIFRyYW5zcGFyZW5jeS5kZXYgVGVzdDEU
MBIGA1UECxMLVHJ1c3RGYWJyaWMxHjAcBgNVBAMTFXRlc3QudHJhbnNwYXJlbmN5
LmRldjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnSx8IVnPfqRf3U
K+3pYMsOaHXIFvLAEmN1UtL2JCoddpkW9gLCGlrQIP4HOpp5v3LY6o5uSWncuQy5
RRbMM78p+YhSSAq46UT/xJzEI6Or7CfPfM5yJrIUQ7mjC9YA9zYTYgGxZSSI5T73
jBUHZXl0w84CdTntHEPPR2m4fSIe9NQ3TY0SXFeNSGH7iw5WtIt68TAWVEuWixM0
OraZLdSz9N+FqcXSGQZbQH7Q9yikvcwRrlzjdKAdvjHky+SoJir/wZLBjaxWjIT7
JZqD5nPd7bRwKp9S2E82CTesra0AeZbbt7DkXSSpu4NRlYFl9g7BI9MiUOiBTcXs
UYidSqECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAULD+M3ORxndJXfyXIfPo/mxxn
pPAwIAYDVR0RBBkwF4IVdGVzdC50cmFuc3BhcmVuY3kuZGV2MA0GCSqGSIb3DQEB
CwUAA4IBAQC5wrX6RII8yv7q+ZpzAEcgh/FDxHgz00ky24GqeodMoQAxl8+C1cFU
1RJQfvFtOq6GmV4v5zea0mjlCYdTwkNybajVpXrfa817WPzTIDBiqDvkJ7GP9Z7o
r16E0JojH3IYObUeYVSU2sw8hWmFchMoj7HinosiGqY+erNgbJastcpdOWaH9g0v
MuxOgOUzy64pUho1AXCj1oHQGh7Gw+xSzCCv4Ma57gMwl/AmuMgkFanDZ+LG94M8
f1AW53bG9zr5HLpO8Pd2hWhh3uUrvMMgm2z/RBqt8oGO8jk2TOrmoIFLOEWcVc3m
CSlFo1FRcayrd+ONAzekIBFwySoySSWp
-----END CERTIFICATE-----`

// Issuance chain 2
// ================
// The next section holds a self signed root, an intermediate, and a leaf cert.

// FakeCACertPEM is a test CA cert for testing.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number:
//	        b6:31:d2:ac:21:ab:65:20
//	Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Validity
//	        Not Before: Jul 11 12:23:26 2016 GMT
//	        Not After : Jul 11 12:23:26 2017 GMT
//	    Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            Public-Key: (2048 bit)
//	            Modulus:
//	                00:a5:41:9a:7a:2d:98:a3:b5:78:6f:15:21:db:0c:
//	                c1:0e:a1:f8:26:f5:b3:b2:67:85:dc:a1:e6:b7:83:
//	                6d:da:63:da:d0:f6:a3:ff:bc:43:f5:2b:9f:00:19:
//	                6e:6b:60:4b:43:20:6e:e2:cb:2e:b6:65:ed:9b:dc:
//	                80:c3:e1:5a:96:af:60:78:0e:0e:fb:8f:ea:3e:3d:
//	                c9:67:8f:a4:57:1c:ba:e4:f3:37:a9:2f:dd:11:9d:
//	                10:5d:e5:d6:ef:d4:3b:06:d9:34:43:42:bb:bb:be:
//	                43:40:2b:e3:b6:d1:b5:6c:58:12:34:96:14:d4:fc:
//	                49:79:c5:26:8c:24:7d:b3:12:f5:f6:3e:b7:41:46:
//	                6b:6d:3a:41:fd:7c:e3:b5:fc:96:6c:c6:cc:ad:8d:
//	                48:09:73:44:64:ea:4f:17:1d:0a:4b:14:5a:19:07:
//	                4a:32:0f:41:2e:e4:85:bd:a1:e1:9b:de:63:7c:3b:
//	                bc:ec:aa:93:2a:0b:a8:c7:24:34:54:42:38:a5:d1:
//	                0c:c4:f9:9e:7c:69:42:71:77:d7:95:aa:bb:13:3d:
//	                f3:cc:c7:5d:b3:fd:76:25:25:e3:da:14:0e:59:81:
//	                e8:2c:58:e8:09:29:7d:22:02:91:95:81:eb:55:6f:
//	                2f:17:b9:af:4a:f3:84:8b:24:6e:ea:14:6b:bb:90:
//	                84:35
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Subject Key Identifier:
//	            01:02:03:04
//	        X509v3 Authority Key Identifier:
//	            keyid:01:02:03:04
//
//	        X509v3 Basic Constraints: critical
//	            CA:TRUE, pathlen:10
//	        X509v3 Key Usage: critical
//	            Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	Signature Algorithm: sha256WithRSAEncryption
//	     92:be:33:eb:d5:d4:32:e7:9e:4e:65:2a:e8:3f:67:b8:f4:d7:
//	     34:ab:95:11:6a:5d:ba:fd:57:9b:94:6e:8d:20:be:fb:7a:e1:
//	     49:ca:39:ea:92:d3:81:5a:b1:87:a3:9f:50:a4:e0:1e:11:de:
//	     c4:d1:07:a1:ca:d1:97:1a:92:bd:73:9a:11:ec:6a:9a:52:11:
//	     2d:40:e1:3b:4f:3c:1f:81:3f:4c:ab:6a:02:84:4f:8b:18:36:
//	     7a:cc:5c:a9:0e:25:2b:cd:57:53:88:d9:eb:82:b1:ce:62:76:
//	     56:d4:23:9e:01:b3:6d:2b:49:ea:d4:3a:c2:f5:76:a7:b3:2d:
//	     24:97:6f:b4:1c:74:6b:95:85:f6:b5:41:56:82:3c:ed:be:96:
//	     1e:5e:6a:2d:7b:f7:fd:7d:6e:3f:fb:c2:ec:61:b3:7c:7f:3b:
//	     f5:9c:64:61:5f:02:93:87:cd:81:f9:7e:53:3e:c1:f5:79:85:
//	     f4:41:87:c7:ca:bd:af:ab:2b:a4:aa:a8:1d:2c:50:ad:23:8f:
//	     db:13:1d:71:8a:85:bd:ac:59:6c:c4:53:c5:71:0c:90:91:f3:
//	     0b:41:ef:da:6e:27:bb:09:57:9c:97:b9:d7:fc:20:96:c5:75:
//	     96:ce:2e:6c:a8:b6:6e:b0:4d:0f:3e:01:95:ea:8b:cd:ae:47:
//	     d0:d9:01:b7
const FakeCACertPEM = `
-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIJALYx0qwhq2UgMA0GCSqGSIb3DQEBCwUAMHExCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0GA1UE
CgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZpY2F0
ZUF1dGhvcml0eTAeFw0xNjA3MTExMjIzMjZaFw0xNzA3MTExMjIzMjZaMHExCzAJ
BgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0G
A1UECgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZp
Y2F0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKVB
mnotmKO1eG8VIdsMwQ6h+Cb1s7Jnhdyh5reDbdpj2tD2o/+8Q/UrnwAZbmtgS0Mg
buLLLrZl7ZvcgMPhWpavYHgODvuP6j49yWePpFccuuTzN6kv3RGdEF3l1u/UOwbZ
NENCu7u+Q0Ar47bRtWxYEjSWFNT8SXnFJowkfbMS9fY+t0FGa206Qf1847X8lmzG
zK2NSAlzRGTqTxcdCksUWhkHSjIPQS7khb2h4ZveY3w7vOyqkyoLqMckNFRCOKXR
DMT5nnxpQnF315WquxM988zHXbP9diUl49oUDlmB6CxY6AkpfSICkZWB61VvLxe5
r0rzhIskbuoUa7uQhDUCAwEAAaNHMEUwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgw
BoAEAQIDBDASBgNVHRMBAf8ECDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwDQYJ
KoZIhvcNAQELBQADggEBAJK+M+vV1DLnnk5lKug/Z7j01zSrlRFqXbr9V5uUbo0g
vvt64UnKOeqS04FasYejn1Ck4B4R3sTRB6HK0Zcakr1zmhHsappSES1A4TtPPB+B
P0yragKET4sYNnrMXKkOJSvNV1OI2euCsc5idlbUI54Bs20rSerUOsL1dqezLSSX
b7QcdGuVhfa1QVaCPO2+lh5eai179/19bj/7wuxhs3x/O/WcZGFfApOHzYH5flM+
wfV5hfRBh8fKva+rK6SqqB0sUK0jj9sTHXGKhb2sWWzEU8VxDJCR8wtB79puJ7sJ
V5yXudf8IJbFdZbOLmyotm6wTQ8+AZXqi82uR9DZAbc=
-----END CERTIFICATE-----`

// FakeIntermediateCertPEM is a test intermediate CA cert.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number: 4792439526061490155 (0x42822a5b866fbfeb)
//	Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Validity
//	        Not Before: May 13 14:26:44 2016 GMT
//	        Not After : Jul 12 14:26:44 2019 GMT
//	    Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            Public-Key: (2048 bit)
//	            Modulus:
//	                00:ca:a4:0c:7a:6d:e9:26:22:d4:67:19:c8:29:40:
//	                c6:bd:cb:44:39:e7:fa:84:01:1d:b3:04:15:48:37:
//	                fa:55:d5:98:4b:2a:ff:14:0e:d6:ce:27:6b:29:d5:
//	                e8:8d:39:eb:be:97:be:53:21:d2:a3:f2:27:ef:46:
//	                68:1c:6f:84:77:85:b4:68:78:7a:d4:3d:50:49:89:
//	                8f:9e:6b:4a:ce:74:c0:0f:c8:68:38:7e:ae:82:ae:
//	                91:0c:6d:87:24:c4:48:f3:e0:8e:a8:3e:0c:f8:e1:
//	                e8:7f:a1:dd:29:f4:d0:eb:3a:b2:38:77:0f:1a:4e:
//	                a6:14:c4:b1:db:5b:ed:f9:a4:f0:9d:1e:d8:a8:d0:
//	                40:28:d6:fc:69:44:0b:37:37:e7:d6:fd:29:b0:70:
//	                36:47:00:89:81:5a:c9:51:cf:2d:a0:80:76:fc:d8:
//	                57:28:87:81:71:e4:10:4b:39:16:51:f2:85:ed:a0:
//	                34:41:bf:f3:52:28:f1:cd:c4:dc:31:f9:26:14:fd:
//	                b6:65:51:2f:76:e9:82:94:fc:2a:be:1a:a0:58:54:
//	                d8:b5:de:e3:96:08:07:50:3d:0e:35:26:e5:3a:c7:
//	                67:e8:8d:b6:f1:34:61:f6:0c:47:d2:fd:0b:51:cf:
//	                a6:99:97:d4:26:a1:12:14:dd:a2:0e:e5:68:4d:75:
//	                f7:c5
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Authority Key Identifier:
//	            keyid:01:02:03:04
//
//	        X509v3 Basic Constraints: critical
//	            CA:TRUE, pathlen:0
//	        X509v3 Key Usage: critical
//	            Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	Signature Algorithm: sha256WithRSAEncryption
//	     01:e2:3a:0c:00:bc:4c:e1:ac:d3:10:54:0c:fc:6b:e4:ac:c8:
//	     c2:00:05:74:39:3f:c5:9b:25:e1:e3:90:88:a9:13:8f:b9:66:
//	     99:2b:65:55:ea:f6:9f:30:39:d9:18:9c:e1:f1:e1:63:62:f4:
//	     f5:46:41:b2:c6:f4:8b:9f:87:d7:e9:93:c7:32:c9:15:83:8b:
//	     e5:76:d3:f0:8d:36:d6:b0:32:ad:c2:95:5d:dd:58:2f:7c:4e:
//	     3e:16:5f:f0:57:0c:27:98:da:32:b8:8d:81:95:f9:db:38:dc:
//	     76:15:d1:3a:01:9a:fb:eb:71:ca:bf:53:bc:d8:30:61:5c:42:
//	     22:81:0a:5c:f9:6d:31:3e:18:cb:eb:65:67:0e:e4:0f:cb:87:
//	     7f:22:d9:84:85:d6:2f:12:7c:35:67:00:e0:65:02:06:66:96:
//	     57:21:78:7a:46:b1:67:d2:9d:db:88:96:55:2f:4e:c4:6f:10:
//	     8b:1a:6a:a7:d5:2e:5e:50:a5:15:c1:3a:af:2d:6e:32:bc:e7:
//	     fd:a0:e9:e6:ab:d6:8c:4f:84:9d:70:f6:17:6c:f9:64:c5:5e:
//	     49:87:91:6b:ca:25:e6:d8:d7:7b:77:39:f4:a3:03:28:5a:45:
//	     2b:7c:85:dc:c3:cc:74:c5:c2:33:e3:1d:3f:21:e9:d5:3b:fe:
//	     13:1d:91:48
const FakeIntermediateCertPEM = `
-----BEGIN CERTIFICATE-----
MIIDnTCCAoWgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcTELMAkGA1UE
BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQK
DAZHb29nbGUxDDAKBgNVBAsMA0VuZzEhMB8GA1UEAwwYRmFrZUNlcnRpZmljYXRl
QXV0aG9yaXR5MB4XDTE2MDUxMzE0MjY0NFoXDTE5MDcxMjE0MjY0NFowcjELMAkG
A1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYD
VQQKDAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVk
aWF0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqk
DHpt6SYi1GcZyClAxr3LRDnn+oQBHbMEFUg3+lXVmEsq/xQO1s4naynV6I05676X
vlMh0qPyJ+9GaBxvhHeFtGh4etQ9UEmJj55rSs50wA/IaDh+roKukQxthyTESPPg
jqg+DPjh6H+h3Sn00Os6sjh3DxpOphTEsdtb7fmk8J0e2KjQQCjW/GlECzc359b9
KbBwNkcAiYFayVHPLaCAdvzYVyiHgXHkEEs5FlHyhe2gNEG/81Io8c3E3DH5JhT9
tmVRL3bpgpT8Kr4aoFhU2LXe45YIB1A9DjUm5TrHZ+iNtvE0YfYMR9L9C1HPppmX
1CahEhTdog7laE1198UCAwEAAaM4MDYwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMB
Af8ECDAGAQH/AgEAMA8GA1UdDwEB/wQFAwMH/4AwDQYJKoZIhvcNAQELBQADggEB
AAHiOgwAvEzhrNMQVAz8a+SsyMIABXQ5P8WbJeHjkIipE4+5ZpkrZVXq9p8wOdkY
nOHx4WNi9PVGQbLG9Iufh9fpk8cyyRWDi+V20/CNNtawMq3ClV3dWC98Tj4WX/BX
DCeY2jK4jYGV+ds43HYV0ToBmvvrccq/U7zYMGFcQiKBClz5bTE+GMvrZWcO5A/L
h38i2YSF1i8SfDVnAOBlAgZmllcheHpGsWfSnduIllUvTsRvEIsaaqfVLl5QpRXB
Oq8tbjK85/2g6ear1oxPhJ1w9hds+WTFXkmHkWvKJebY13t3OfSjAyhaRSt8hdzD
zHTFwjPjHT8h6dU7/hMdkUg=
-----END CERTIFICATE-----`

// LeafSignedByFakeIntermediateCertPEM is a test cert signed by the intermediate CA.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number: 4792439526061490155 (0x42822a5b866fbfeb)
//	Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//	    Validity
//	        Not Before: May 13 14:26:44 2016 GMT
//	        Not After : Jul 12 14:26:44 2019 GMT
//	    Subject: C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com, SN=RFC5280 s4.2.1.9 'The pathLenConstraint field ... gives the maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path.', GN=Intermediate CA cert used to sign
//	    Subject Public Key Info:
//	        Public Key Algorithm: id-ecPublicKey
//	            Public-Key: (256 bit)
//	                04:c4:09:39:84:f5:15:8d:12:54:b2:02:9c:f9:01:
//	                e2:6d:35:47:d4:0d:d0:11:61:66:09:35:1d:cb:12:
//	                14:95:b2:3f:ff:35:bd:22:8e:4d:fc:38:50:2d:22:
//	                d6:98:1e:ca:a0:23:af:a4:96:7e:32:d1:82:5f:31:
//	                57:fb:28:ff:37
//	            ASN1 OID: prime256v1
//	            NIST CURVE: P-256
//	    X509v3 extensions:
//	        X509v3 Extended Key Usage:
//	            TLS Web Server Authentication, TLS Web Client Authentication
//	        X509v3 Subject Alternative Name:
//	            DNS:*.google.com, DNS:*.android.com, DNS:*.appengine.google.com, DNS:*.cloud.google.com,
//	            DNS:*.google-analytics.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google.co.in, DNS:*.google.co.jp,
//	            DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co,
//	            DNS:*.google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google.de, DNS:*.google.es,
//	            DNS:*.google.fr, DNS:*.google.hu, DNS:*.google.it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt,
//	            DNS:*.googleadapis.com, DNS:*.googleapis.cn, DNS:*.googlecommerce.com, DNS:*.googlevideo.com,
//	            DNS:*.gstatic.cn, DNS:*.gstatic.com, DNS:*.gvt1.com, DNS:*.gvt2.com, DNS:*.metric.gstatic.com,
//	            DNS:*.urchin.com, DNS:*.url.google.com, DNS:*.youtube-nocookie.com, DNS:*.youtube.com,
//	            DNS:*.youtubeeducation.com, DNS:*.ytimg.com, DNS:android.clients.google.com, DNS:android.com, DNS:g.co,
//	            DNS:goo.gl, DNS:google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:urchin.com,
//	            DNS:youtu.be, DNS:youtube.com, DNS:youtubeeducation.com
//	        X509v3 Key Usage:
//	            Digital Signature
//	        Authority Information Access:
//	            CA Issuers - URI:http://pki.google.com/GIAG2.crt
//	            OCSP - URI:http://clients1.google.com/ocsp
//
//	        X509v3 Subject Key Identifier:
//	            DB:F4:6E:63:EE:E2:DC:BE:BF:38:60:4F:98:31:D0:64:44:F1:63:D8
//	        X509v3 Basic Constraints: critical
//	            CA:FALSE
//	        X509v3 Certificate Policies:
//	            Policy: 1.3.6.1.4.1.11129.2.5.1
//	            Policy: 2.23.140.1.2.2
//
//	        X509v3 CRL Distribution Points:
//
//	            Full Name:
//	              URI:http://pki.google.com/GIAG2.crl
//
//	Signature Algorithm: sha256WithRSAEncryption
//	     0e:a6:6f:79:7d:38:4b:60:f0:c1:76:9c:4e:92:f5:24:ce:12:
//	     34:72:94:95:8d:cf:1c:0c:d6:78:6b:ee:66:2b:50:36:22:7a:
//	     be:ff:22:c7:dd:93:2c:40:83:2f:a0:37:29:8f:bb:98:22:bf:
//	     8e:c6:6c:b4:8b:8f:e9:1e:0f:bd:8a:df:df:f5:c9:aa:79:ac:
//	     00:e6:ca:a6:1a:74:8e:67:f9:5f:09:82:3c:f9:b4:5b:30:85:
//	     0b:ae:28:c2:b8:9c:23:7c:6a:59:66:ca:8e:bd:20:6e:20:e4:
//	     b3:46:f8:06:56:99:5c:b3:47:62:b6:e4:f6:92:10:85:ae:46:
//	     e5:c1:af:c1:a8:8a:b3:b6:f3:fb:2e:e1:26:56:98:e4:aa:de:
//	     29:0b:71:ef:0f:45:d4:c6:ce:4f:21:d6:59:18:89:df:7a:ac:
//	     a6:93:97:de:45:e5:87:06:e3:c7:a4:f2:14:39:b2:b1:99:0b:
//	     7e:85:cc:3a:62:c1:c4:fb:40:7c:e1:7b:71:f4:13:1e:e2:aa:
//	     94:7e:ba:a6:b5:65:e7:f6:e9:c1:c3:1a:92:62:c0:aa:c4:74:
//	     29:43:ee:f4:a6:6b:81:c6:50:7d:b3:a2:d2:b4:8c:c4:f6:cc:
//	     9a:0e:65:32:8f:14:65:8c:a0:30:20:d5:7a:cf:48:fb:84:a4:
//	     3a:30:fa:44
const LeafSignedByFakeIntermediateCertPEM = `
-----BEGIN CERTIFICATE-----
MIIH6DCCBtCgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcjELMAkGA1UE
BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQK
DAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVkaWF0
ZUF1dGhvcml0eTAeFw0xNjA1MTMxNDI2NDRaFw0xOTA3MTIxNDI2NDRaMIIBWDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50
YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJbmMxFTATBgNVBAMMDCouZ29vZ2xl
LmNvbTGBwzCBwAYDVQQEDIG4UkZDNTI4MCBzNC4yLjEuOSAnVGhlIHBhdGhMZW5D
b25zdHJhaW50IGZpZWxkIC4uLiBnaXZlcyB0aGUgbWF4aW11bSBudW1iZXIgb2Yg
bm9uLXNlbGYtaXNzdWVkIGludGVybWVkaWF0ZSBjZXJ0aWZpY2F0ZXMgdGhhdCBt
YXkgZm9sbG93IHRoaXMgY2VydGlmaWNhdGUgaW4gYSB2YWxpZCBjZXJ0aWZpY2F0
aW9uIHBhdGguJzEqMCgGA1UEKgwhSW50ZXJtZWRpYXRlIENBIGNlcnQgdXNlZCB0
byBzaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExAk5hPUVjRJUsgKc+QHi
bTVH1A3QEWFmCTUdyxIUlbI//zW9Io5N/DhQLSLWmB7KoCOvpJZ+MtGCXzFX+yj/
N6OCBGMwggRfMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCCA0IGA1Ud
EQSCAzkwggM1ggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22CFiouYXBwZW5n
aW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIWKi5nb29nbGUtYW5h
bHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2dsZS5j
by5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2dsZS5j
b20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdvb2ds
ZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8qLmdv
b2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29nbGUu
ZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyouZ29v
Z2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdvb2ds
ZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNv
bYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tggoqLmd2dDEuY29tggoqLmd2
dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29tghAqLnVy
bC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUu
Y29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNvbYIaYW5kcm9p
ZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tggRnLmNvggZnb28uZ2yC
FGdvb2dsZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29tghJnb29nbGVjb21tZXJj
ZS5jb22CCnVyY2hpbi5jb22CCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHVi
ZWVkdWNhdGlvbi5jb20wDAYDVR0PBAUDAweAADBoBggrBgEFBQcBAQRcMFowKwYI
KwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcnQwKwYIKwYB
BQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29jc3AwHQYDVR0OBBYE
FNv0bmPu4ty+vzhgT5gx0GRE8WPYMAwGA1UdEwEB/wQCMAAwIQYDVR0gBBowGDAM
BgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8v
cGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAOpm95
fThLYPDBdpxOkvUkzhI0cpSVjc8cDNZ4a+5mK1A2Inq+/yLH3ZMsQIMvoDcpj7uY
Ir+Oxmy0i4/pHg+9it/f9cmqeawA5sqmGnSOZ/lfCYI8+bRbMIULrijCuJwjfGpZ
ZsqOvSBuIOSzRvgGVplcs0dituT2khCFrkblwa/BqIqztvP7LuEmVpjkqt4pC3Hv
D0XUxs5PIdZZGInfeqymk5feReWHBuPHpPIUObKxmQt+hcw6YsHE+0B84Xtx9BMe
4qqUfrqmtWXn9unBwxqSYsCqxHQpQ+70pmuBxlB9s6LStIzE9syaDmUyjxRljKAw
INV6z0j7hKQ6MPpE
-----END CERTIFICATE-----`

// Issuance chain 3
// ================
// The next section holds a self signed root, intermediate certs
// with various policy constraints, and a leaf cert.

// The matching certificate and private key are stored in pem format
// in this directory.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number: 67554046 (0x406cafe)
//	Signature Algorithm: ecdsa-with-SHA256
//	    Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Validity
//	        Not Before: Dec  7 15:13:36 2016 GMT
//	        Not After : Dec  5 15:13:36 2026 GMT
//	    Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Subject Public Key Info:
//	        Public Key Algorithm: id-ecPublicKey
//	            Public-Key: (256 bit)
//	            pub:
//	                04:f2:d3:07:ef:7e:df:cf:ce:f4:f4:0a:5b:bc:9e:
//	                3f:cb:1c:fd:0c:46:dc:85:fb:c1:f6:d3:b2:ba:1d:
//	                51:f1:98:6c:48:a8:15:46:45:63:ca:df:d6:c9:ac:
//	                cf:60:3b:c7:4e:dd:b8:d2:16:ab:a0:09:24:1d:09:
//	                66:1e:4d:eb:a1
//	            ASN1 OID: prime256v1
//	            NIST CURVE: P-256
//	    X509v3 extensions:
//	        X509v3 Subject Key Identifier:
//	            01:02:03:04
//	        X509v3 Authority Key Identifier:
//	            keyid:01:02:03:04
//	        X509v3 Basic Constraints: critical
//	            CA:TRUE, pathlen:10
//	        X509v3 Key Usage: critical
//	            Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	Signature Algorithm: ecdsa-with-SHA256
//	     30:46:02:21:00:a6:28:49:39:43:6f:80:e4:43:a6:1e:3b:aa:
//	     89:5e:c2:25:60:2a:e1:39:bd:55:43:ae:4d:5c:a9:a6:ef:ac:
//	     65:02:21:00:c9:c5:08:c6:59:93:b4:86:70:a5:6b:54:2b:5b:
//	     fc:0c:88:6b:b0:23:07:2b:c7:0c:27:de:87:2d:96:80:d5:56
const FakeRootCACertPEM = `
-----BEGIN CERTIFICATE-----
MIICHDCCAcGgAwIBAgIEBAbK/jAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTYxMjA3MTUxMzM2WhcNMjYxMjA1MTUxMzM2WjBxMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRo
b3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATy0wfvft/PzvT0Clu8nj/L
HP0MRtyF+8H207K6HVHxmGxIqBVGRWPK39bJrM9gO8dO3bjSFqugCSQdCWYeTeuh
o0cwRTANBgNVHQ4EBgQEAQIDBDAPBgNVHSMECDAGgAQBAgMEMBIGA1UdEwEB/wQI
MAYBAf8CAQowDwYDVR0PAQH/BAUDAwf/gDAKBggqhkjOPQQDAgNJADBGAiEApihJ
OUNvgORDph47qolewiVgKuE5vVVDrk1cqabvrGUCIQDJxQjGWZO0hnCla1QrW/wM
iGuwIwcrxwwn3octloDVVg==
-----END CERTIFICATE-----`

// Data:
//
//	Version: 3 (0x2)
//	Serial Number: 1111638594 (0x42424242)
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	Validity
//	    Not Before: Feb 13 09:33:59 2018 GMT
//	    Not After : Dec 23 09:33:59 2027 GMT
//	Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//	            02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//	            a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//	            c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//	            5d:98:5f:5d:5d
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Subject Key Identifier:
//	        01:02:03:04
//	    X509v3 Authority Key Identifier:
//	        keyid:01:02:03:04
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE, pathlen:10
//	    X509v3 Policy Constraints: critical
//	        Require Explicit Policy:0
//	    X509v3 Key Usage: critical
//	        Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	30:44:02:20:4c:aa:27:8f:d9:83:32:76:40:17:a1:a8:00:1d:
//	bc:d1:45:b2:53:c6:47:77:48:f1:c3:89:68:5d:f4:7f:5c:52:
//	02:20:39:68:40:5c:fd:f0:2a:e2:3f:34:45:b3:19:2d:e3:4d:
//	58:cd:76:42:19:09:cf:5c:1c:e5:f1:71:e0:39:62:b9
const FakeIntermediateWithPolicyConstraintsCertPEM = `
-----BEGIN CERTIFICATE-----
MIICLDCCAdOgAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMDkzMzU5WhcNMjcxMjIzMDkzMzU5WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNYMFYwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdJAEB/wQFMAOAAQAwDwYDVR0PAQH/BAUDAwf/gDAKBggq
hkjOPQQDAgNHADBEAiBMqieP2YMydkAXoagAHbzRRbJTxkd3SPHDiWhd9H9cUgIg
OWhAXP3wKuI/NEWzGS3jTVjNdkIZCc9cHOXxceA5Yrk=
-----END CERTIFICATE-----`

// Data:
//
//	Version: 3 (0x2)
//	Serial Number: 1111638594 (0x42424242)
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	Validity
//	    Not Before: Feb 13 11:33:08 2018 GMT
//	    Not After : Dec 23 11:33:08 2027 GMT
//	Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//	            02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//	            a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//	            c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//	            5d:98:5f:5d:5d
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Subject Key Identifier:
//	        01:02:03:04
//	    X509v3 Authority Key Identifier:
//	        keyid:01:02:03:04
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE, pathlen:10
//	    X509v3 Key Usage: critical
//	        Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	    X509v3 Name Constraints:
//	        Permitted:
//	          DNS:.csr.pem
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	30:46:02:21:00:fd:11:41:d8:1f:2b:b5:49:8e:27:6e:70:93:
//	2c:f1:c2:e7:b0:a2:40:e2:c6:89:45:fc:99:a5:9b:dc:21:fb:
//	f6:02:21:00:b7:4f:98:bf:1f:dc:92:e7:db:7c:aa:33:7a:40:
//	36:1d:58:19:aa:96:3d:5e:5b:46:5f:47:f6:e3:7d:75:19:4f
const FakeIntermediateWithNameConstraintsCertPEM = `
-----BEGIN CERTIFICATE-----
MIICNjCCAdugAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMTEzMzA4WhcNMjcxMjIzMTEzMzA4WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNgMF4wDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwFwYDVR0eBBAwDqAMMAqCCC5jc3Iu
cGVtMAoGCCqGSM49BAMCA0kAMEYCIQD9EUHYHyu1SY4nbnCTLPHC57CiQOLGiUX8
maWb3CH79gIhALdPmL8f3JLn23yqM3pANh1YGaqWPV5bRl9H9uN9dRlP
-----END CERTIFICATE-----`

// Data:
//
//	Version: 3 (0x2)
//	Serial Number: 1111638594 (0x42424242)
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	Validity
//	    Not Before: Feb 13 11:42:37 2018 GMT
//	    Not After : Dec 23 11:42:37 2027 GMT
//	Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//	Subject Public Key Info:
//	    Public Key Algorithm: id-ecPublicKey
//	        Public-Key: (256 bit)
//	        pub:
//	            04:f1:bf:2d:e8:8c:66:40:e3:a8:d1:54:e0:42:49:
//	            02:cb:dd:47:08:85:c2:67:41:4c:eb:f7:87:cd:8d:
//	            a3:09:c8:18:cc:2e:30:53:16:32:aa:d5:9c:08:73:
//	            c6:76:fa:fa:3a:38:e9:34:35:9c:51:d1:ee:12:81:
//	            5d:98:5f:5d:5d
//	        ASN1 OID: prime256v1
//	        NIST CURVE: P-256
//	X509v3 extensions:
//	    X509v3 Subject Key Identifier:
//	        01:02:03:04
//	    X509v3 Authority Key Identifier:
//	        keyid:01:02:03:04
//
//	    X509v3 Basic Constraints: critical
//	        CA:TRUE, pathlen:10
//	    X509v3 Key Usage: critical
//	        Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	    X509v3 Name Constraints:
//	        Permitted:
//	          DNS:.xyzzy.pem
//
// Signature Algorithm: ecdsa-with-SHA256
//
//	30:45:02:20:3f:0a:40:60:b6:9e:ea:a5:cd:eb:e4:0e:7c:bc:
//	40:22:b2:e2:14:07:e8:ab:fa:4a:85:2a:41:18:20:f0:31:1a:
//	02:21:00:a4:64:91:6d:79:47:79:0f:16:06:62:a9:88:8b:92:
//	6d:40:fa:54:cb:c9:4f:bc:3f:53:27:e5:cd:12:16:53:7a
const FakeIntermediateWithInvalidNameConstraintsCertPEM = `
-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgIEQkJCQjAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJHQjEP
MA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdvb2ds
ZTEMMAoGA1UECxMDRW5nMSEwHwYDVQQDExhGYWtlQ2VydGlmaWNhdGVBdXRob3Jp
dHkwHhcNMTgwMjEzMTE0MjM3WhcNMjcxMjIzMTE0MjM3WjByMQswCQYDVQQGEwJH
QjEPMA0GA1UECBMGTG9uZG9uMQ8wDQYDVQQHEwZMb25kb24xDzANBgNVBAoTBkdv
b2dsZTEMMAoGA1UECxMDRW5nMSIwIAYDVQQDExlGYWtlSW50ZXJtZWRpYXRlQXV0
aG9yaXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8b8t6IxmQOOo0VTgQkkC
y91HCIXCZ0FM6/eHzY2jCcgYzC4wUxYyqtWcCHPGdvr6OjjpNDWcUdHuEoFdmF9d
XaNiMGAwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8E
CDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwGQYDVR0eBBIwEKAOMAyCCi54eXp6
eS5wZW0wCgYIKoZIzj0EAwIDSAAwRQIgPwpAYLae6qXN6+QOfLxAIrLiFAfoq/pK
hSpBGCDwMRoCIQCkZJFteUd5DxYGYqmIi5JtQPpUy8lPvD9TJ+XNEhZTeg==
-----END CERTIFICATE-----`

// LeafCertPEM is a leaf cert signed by the key in:
//
//   - FakeIntermediateWithPolicyConstraintsCertPEM
//
//   - FakeIntermediateWithNameConstraintsCertPEM
//
//   - FakeIntermediateWithInvalidNameConstraintsCertPEM
//
//     Data:
//     Version: 3 (0x2)
//     Serial Number: 3735928559 (0xdeadbeef)
//     Signature Algorithm: ecdsa-with-SHA256
//     Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeIntermediateAuthority
//     Validity
//     Not Before: Feb 13 11:38:39 2018 GMT
//     Not After : Mar 28 11:38:39 2025 GMT
//     Subject: C=GB, ST=London, O=Google, OU=Eng, CN=leaf01.csr.pem
//     Subject Public Key Info:
//     Public Key Algorithm: id-ecPublicKey
//     Public-Key: (256 bit)
//     pub:
//     04:eb:37:4e:52:45:9c:46:d5:a8:b8:c5:ed:58:b9:
//     30:29:a6:70:8a:69:a0:26:5c:9e:2f:6e:b8:6b:23:
//     6c:84:e1:46:3a:98:36:82:44:a5:8a:17:8b:41:82:
//     32:f4:2d:e0:08:5b:7e:07:38:52:fc:47:56:28:27:
//     9b:ed:60:8b:ac
//     ASN1 OID: prime256v1
//     NIST CURVE: P-256
//     X509v3 extensions:
//     X509v3 Subject Key Identifier:
//     3F:B2:2F:41:FC:11:9A:D3:8D:A6:85:80:84:86:AE:7E:73:2E:69:5D
//     X509v3 Authority Key Identifier:
//     keyid:01:02:03:04
//     X509v3 Key Usage: critical
//     Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Encipher Only, Decipher Only
//     X509v3 Subject Alternative Name:
//     DNS:leaf01.csr.pem
//     Signature Algorithm: ecdsa-with-SHA256
//     30:46:02:21:00:b5:2a:f3:39:1e:06:b7:77:b2:ad:a8:83:1b:
//     83:38:64:5e:3a:25:51:e9:57:1f:00:53:72:db:08:11:65:3d:
//     f4:02:21:00:a1:4e:5d:b5:9a:8b:10:6e:15:a3:2a:bd:d9:80:
//     91:96:7c:1a:4f:8f:91:dc:44:9f:13:ff:57:f0:5e:ce:32:34
const LeafCertPEM = `
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIFAN6tvu8wCgYIKoZIzj0EAwIwcjELMAkGA1UEBhMCR0Ix
DzANBgNVBAgTBkxvbmRvbjEPMA0GA1UEBxMGTG9uZG9uMQ8wDQYDVQQKEwZHb29n
bGUxDDAKBgNVBAsTA0VuZzEiMCAGA1UEAxMZRmFrZUludGVybWVkaWF0ZUF1dGhv
cml0eTAeFw0xODAyMTMxMTM4MzlaFw0yNTAzMjgxMTM4MzlaMFYxCzAJBgNVBAYT
AkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAoMBkdvb2dsZTEMMAoGA1UECwwD
RW5nMRcwFQYDVQQDDA5sZWFmMDEuY3NyLnBlbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABOs3TlJFnEbVqLjF7Vi5MCmmcIppoCZcni9uuGsjbIThRjqYNoJEpYoX
i0GCMvQt4Ahbfgc4UvxHVignm+1gi6yjXjBcMB0GA1UdDgQWBBQ/si9B/BGa042m
hYCEhq5+cy5pXTAPBgNVHSMECDAGgAQBAgMEMA8GA1UdDwEB/wQFAwMH+YAwGQYD
VR0RBBIwEIIObGVhZjAxLmNzci5wZW0wCgYIKoZIzj0EAwIDSQAwRgIhALUq8zke
Brd3sq2ogxuDOGReOiVR6VcfAFNy2wgRZT30AiEAoU5dtZqLEG4Voyq92YCRlnwa
T4+R3ESfE/9X8F7OMjQ=
-----END CERTIFICATE-----`

// Issuance chain 4
// ================
// The next section holds a real world intermediate and leaf cert.

// RealPrecertIntermediatePEM is the intermediate issuer for
// RealPrecertWithEKUPEM, below.
//
// Certificate:
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number:
//	        01:e3:b4:9d:77:cd:f4:0c:06:19:16:b6:e3
//	    Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: OU = GlobalSign Root CA - R2, O = GlobalSign, CN = GlobalSign
//	    Validity
//	        Not Before: Jun 15 00:00:42 2017 GMT
//	        Not After : Dec 15 00:00:42 2021 GMT
//	    Subject: C = US, O = Google Trust Services, CN = GTS CA 1D2
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            RSA Public-Key: (2048 bit)
//	            Modulus:
//	                00:b2:d9:7b:e1:e1:d7:3f:1c:91:72:ff:f9:10:cd:
//	                87:15:79:74:b7:3e:47:8b:b2:61:55:fd:0c:36:c6:
//	                7e:77:42:3a:b2:fa:52:5b:0b:71:81:d6:4d:d5:e9:
//	                2b:24:4d:23:5e:8b:2b:72:5f:21:55:b5:29:ef:44:
//	                cb:eb:82:52:ab:3e:27:a4:92:49:41:4a:de:a8:dd:
//	                31:e0:3c:df:6d:7a:4d:2d:d6:6d:09:b0:0e:e3:61:
//	                f2:b2:fe:90:6c:5a:7b:10:64:49:b4:0b:3c:08:f2:
//	                ea:79:0c:6c:a6:1a:89:6a:56:32:a0:29:a2:30:82:
//	                8f:81:51:0c:f3:a2:b9:d9:75:b9:22:9e:27:14:ba:
//	                4a:2f:2c:63:58:87:f1:5d:10:e6:5f:91:bb:b9:5b:
//	                cc:47:e2:1e:75:b6:8c:8f:cc:75:5d:57:05:e7:82:
//	                c6:84:0e:74:72:2a:cb:3b:55:f5:6e:70:eb:66:69:
//	                c3:24:bb:38:93:35:9b:68:61:2f:9b:d6:ae:a6:77:
//	                72:7c:71:48:58:33:10:af:e9:80:82:1d:b5:07:40:
//	                1b:f6:3d:ec:a2:ad:47:9d:b4:94:29:34:b3:8c:2f:
//	                cd:25:03:58:35:c0:25:a4:55:5f:e1:b3:07:56:3d:
//	                c8:d0:63:b8:20:fb:8c:1d:43:2c:f8:f9:a9:d5:ec:
//	                6f:97
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Key Usage: critical
//	            Digital Signature, Certificate Sign, CRL Sign
//	        X509v3 Extended Key Usage:
//	            TLS Web Server Authentication, TLS Web Client Authentication
//	        X509v3 Basic Constraints: critical
//	            CA:TRUE, pathlen:0
//	        X509v3 Subject Key Identifier:
//	            B1:DD:32:5D:E8:B7:37:72:D2:CE:5C:CE:26:FE:47:79:E2:01:08:E9
//	        X509v3 Authority Key Identifier:
//	            keyid:9B:E2:07:57:67:1C:1E:C0:6A:06:DE:59:B4:9A:2D:DF:DC:19:86:2E
//
//	        Authority Information Access:
//	            OCSP - URI:http://ocsp.pki.goog/gsr2
//
//	        X509v3 CRL Distribution Points:
//
//	            Full Name:
//	              URI:http://crl.pki.goog/gsr2/gsr2.crl
//
//	        X509v3 Certificate Policies:
//	            Policy: 2.23.140.1.2.1
//	              CPS: https://pki.goog/repository/
//
//	Signature Algorithm: sha256WithRSAEncryption
//	     71:4a:c4:c3:23:ae:f7:e3:b2:02:79:8c:13:e8:53:8e:80:c5:
//	     f0:e3:ef:71:60:a9:a9:7b:34:65:85:34:bd:47:3b:03:57:16:
//	     00:99:48:3a:e0:e0:f0:ea:cd:b6:48:3c:d5:ab:72:f0:d0:1b:
//	     cb:64:2d:3b:0d:74:68:d7:74:88:31:7c:6a:ba:0e:f0:8c:4d:
//	     78:ce:da:10:f4:8a:96:45:97:a9:97:ad:c5:35:1a:18:64:e8:
//	     93:b6:0d:9d:1f:b9:5e:1d:80:ea:e7:5b:9c:8e:ae:0e:a6:84:
//	     d2:d1:17:ce:b3:fb:f6:81:4f:3c:e6:68:9f:cf:f1:a6:76:c5:
//	     7d:a7:f3:dd:7d:58:0f:e0:f6:61:01:1c:51:8e:76:33:2b:48:
//	     9d:5c:81:51:72:08:17:ba:fd:01:d3:ee:46:f9:f4:b2:68:40:
//	     99:31:01:6c:4f:1b:c6:56:eb:81:73:d2:79:52:05:92:26:5b:
//	     71:cd:9d:c4:d2:ce:23:77:0f:41:7a:69:5e:21:25:c6:f8:b7:
//	     ff:7a:f7:47:de:c2:00:7b:9c:5a:45:9c:2a:4e:46:90:d9:75:
//	     2c:d8:ff:8c:ee:cc:dc:69:eb:6c:e6:15:d0:a3:ff:48:0b:ac:
//	     55:df:df:25:9d:42:b6:51:a3:66:95:60:c5:d0:22:e7:22:7a:
//	     51:a5:cc:87
const RealPrecertIntermediatePEM = `
-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgINAeO0nXfN9AwGGRa24zANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxRDIwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCy2Xvh4dc/HJFy//kQzYcVeXS3PkeLsmFV/Qw2xn53Qjqy
+lJbC3GB1k3V6SskTSNeiytyXyFVtSnvRMvrglKrPiekkklBSt6o3THgPN9tek0t
1m0JsA7jYfKy/pBsWnsQZEm0CzwI8up5DGymGolqVjKgKaIwgo+BUQzzornZdbki
nicUukovLGNYh/FdEOZfkbu5W8xH4h51toyPzHVdVwXngsaEDnRyKss7VfVucOtm
acMkuziTNZtoYS+b1q6md3J8cUhYMxCv6YCCHbUHQBv2PeyirUedtJQpNLOML80l
A1g1wCWkVV/hswdWPcjQY7gg+4wdQyz4+anV7G+XAgMBAAGjggEzMIIBLzAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLHdMl3otzdy0s5czib+R3niAQjpMB8G
A1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl
BggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp
MCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g
BDgwNjA0BgZngQwBAgEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y
ZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAcUrEwyOu9+OyAnmME+hTjoDF
8OPvcWCpqXs0ZYU0vUc7A1cWAJlIOuDg8OrNtkg81aty8NAby2QtOw10aNd0iDF8
aroO8IxNeM7aEPSKlkWXqZetxTUaGGTok7YNnR+5Xh2A6udbnI6uDqaE0tEXzrP7
9oFPPOZon8/xpnbFfafz3X1YD+D2YQEcUY52MytInVyBUXIIF7r9AdPuRvn0smhA
mTEBbE8bxlbrgXPSeVIFkiZbcc2dxNLOI3cPQXppXiElxvi3/3r3R97CAHucWkWc
Kk5GkNl1LNj/jO7M3GnrbOYV0KP/SAusVd/fJZ1CtlGjZpVgxdAi5yJ6UaXMhw==
-----END CERTIFICATE-----
`

// RealPrecertWithEKUPEM is an actual precertificate containing a valid EKU.
//
// Certificate:
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number:
//	        9c:a4:07:e2:25:f9:7c:c2:0a:00:00:00:00:20:6e:e5
//	    Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: C = US, O = Google Trust Services, CN = GTS CA 1D2
//	    Validity
//	        Not Before: Mar 23 12:23:44 2020 GMT
//	        Not After : Jun 21 12:23:44 2020 GMT
//	    Subject: CN = certificate.transparency.dev
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            RSA Public-Key: (2048 bit)
//	            Modulus:
//	                00:a8:7e:59:c0:e5:3b:da:3c:bf:04:51:91:eb:9f:
//	                6c:1b:cf:9f:90:dc:22:89:1c:b5:98:24:69:2e:26:
//	                2d:61:92:04:0f:2e:f1:da:ec:ea:3a:d9:cc:3a:82:
//	                e2:b8:3a:7d:6c:79:79:f7:36:c5:52:a4:bb:46:1d:
//	                2f:0b:6c:5f:00:31:af:24:e9:4a:1b:32:63:1a:b5:
//	                c3:28:9c:a7:0a:b5:73:e2:c1:a7:b5:1e:11:ae:cd:
//	                19:79:0c:62:06:cf:80:f0:ed:e2:72:82:bb:b4:84:
//	                0e:9d:c9:7d:3b:fb:4e:05:49:3a:14:0f:86:92:01:
//	                49:52:2c:cc:a0:e1:ef:86:fe:18:00:83:69:6c:90:
//	                c6:7b:a9:42:df:57:9c:7b:61:06:80:23:b2:5f:95:
//	                95:1e:9b:34:6f:ab:a3:21:1b:2b:8e:9f:34:4f:ec:
//	                e8:9a:48:74:81:2f:9b:12:67:54:a1:46:76:96:9a:
//	                1e:9d:c3:ee:bf:6a:e8:49:72:57:28:b1:12:c4:ca:
//	                41:84:96:f7:32:4a:4a:9e:59:2d:48:3e:ac:29:0c:
//	                f4:f4:03:28:33:1a:73:10:48:29:68:12:e3:f9:7e:
//	                f4:5f:01:54:b0:73:c6:a8:72:b6:84:54:05:23:36:
//	                b6:db:3f:d8:e5:27:89:4c:dc:bb:b1:c9:9e:e7:7e:
//	                b0:b5
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Key Usage: critical
//	            Digital Signature, Key Encipherment
//	        X509v3 Extended Key Usage:
//	            TLS Web Server Authentication
//	        X509v3 Basic Constraints: critical
//	            CA:FALSE
//	        X509v3 Subject Key Identifier:
//	            B8:E0:AF:4F:7C:48:F3:FF:EB:FC:5E:A5:34:36:2D:56:54:AC:97:6B
//	        X509v3 Authority Key Identifier:
//	            keyid:B1:DD:32:5D:E8:B7:37:72:D2:CE:5C:CE:26:FE:47:79:E2:01:08:E9
//
//	        Authority Information Access:
//	            OCSP - URI:http://ocsp.pki.goog/gts1d2
//	            CA Issuers - URI:http://pki.goog/gsr2/GTS1D2.crt
//
//	        X509v3 Subject Alternative Name:
//	            DNS:certificate.transparency.dev
//	        X509v3 Certificate Policies:
//	            Policy: 2.23.140.1.2.1
//	            Policy: 1.3.6.1.4.1.11129.2.5.3
//
//	        X509v3 CRL Distribution Points:
//
//	            Full Name:
//	              URI:http://crl.pki.goog/GTS1D2.crl
//
//	        CT Precertificate Poison: critical
//	            NULL
//	Signature Algorithm: sha256WithRSAEncryption
//	     51:fe:93:53:7a:e1:6d:34:ce:a2:1d:4d:32:c5:39:a5:e8:1e:
//	     ee:97:56:33:84:5a:5e:5c:be:13:64:92:66:df:a7:79:82:c8:
//	     35:c6:4d:8f:ff:da:a1:cc:4d:70:b0:a7:1c:73:69:d5:08:ea:
//	     53:f4:8e:73:27:5a:9d:5a:c7:39:0a:19:dd:51:21:94:3c:31:
//	     b5:cd:06:2d:50:bf:90:09:3e:62:ca:a3:bf:f2:74:9d:2b:33:
//	     38:e9:9f:f1:b7:2f:e2:3c:e4:8a:d4:63:57:c7:bd:27:fd:94:
//	     15:c5:03:82:95:35:79:d6:84:0f:90:01:47:53:af:ed:12:d6:
//	     9c:63:04:1b:06:83:87:83:a1:34:f0:05:d8:8b:c6:b9:39:ce:
//	     9c:32:ac:bf:04:d5:8d:b8:2f:ee:61:55:b9:f3:b9:b8:93:c7:
//	     6d:9c:39:68:b4:39:d8:67:5d:cb:5b:bd:d5:a1:b8:d9:18:16:
//	     7c:f3:ff:7a:77:d9:cc:68:f3:c8:ee:b4:52:06:37:6c:8e:23:
//	     69:1c:49:81:1c:08:26:80:a1:05:8b:ed:f5:dc:33:c6:84:7a:
//	     e3:ef:2f:c3:22:02:a0:33:8d:48:61:8a:98:27:34:e8:75:5d:
//	     eb:56:93:a3:be:2e:c5:04:ab:d6:88:cc:53:c6:9c:db:9f:aa:
//	     5d:eb:c6:82
const RealPrecertWithEKUPEM = `
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIRAJykB+Il+XzCCgAAAAAgbuUwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFEMjAeFw0yMDAzMjMxMjIzNDRaFw0yMDA2MjExMjIz
NDRaMCcxJTAjBgNVBAMTHGNlcnRpZmljYXRlLnRyYW5zcGFyZW5jeS5kZXYwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoflnA5TvaPL8EUZHrn2wbz5+Q
3CKJHLWYJGkuJi1hkgQPLvHa7Oo62cw6guK4On1seXn3NsVSpLtGHS8LbF8AMa8k
6UobMmMatcMonKcKtXPiwae1HhGuzRl5DGIGz4Dw7eJygru0hA6dyX07+04FSToU
D4aSAUlSLMyg4e+G/hgAg2lskMZ7qULfV5x7YQaAI7JflZUemzRvq6MhGyuOnzRP
7OiaSHSBL5sSZ1ShRnaWmh6dw+6/auhJclcosRLEykGElvcySkqeWS1IPqwpDPT0
AygzGnMQSCloEuP5fvRfAVSwc8aocraEVAUjNrbbP9jlJ4lM3LuxyZ7nfrC1AgMB
AAGjggFvMIIBazAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUuOCvT3xI8//r/F6lNDYtVlSsl2swHwYD
VR0jBBgwFoAUsd0yXei3N3LSzlzOJv5HeeIBCOkwZAYIKwYBBQUHAQEEWDBWMCcG
CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxZDIwKwYIKwYBBQUH
MAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFEMi5jcnQwJwYDVR0RBCAwHoIc
Y2VydGlmaWNhdGUudHJhbnNwYXJlbmN5LmRldjAhBgNVHSAEGjAYMAgGBmeBDAEC
ATAMBgorBgEEAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwucGtp
Lmdvb2cvR1RTMUQyLmNybDATBgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0B
AQsFAAOCAQEAUf6TU3rhbTTOoh1NMsU5pege7pdWM4RaXly+E2SSZt+neYLINcZN
j//aocxNcLCnHHNp1QjqU/SOcydanVrHOQoZ3VEhlDwxtc0GLVC/kAk+Ysqjv/J0
nSszOOmf8bcv4jzkitRjV8e9J/2UFcUDgpU1edaED5ABR1Ov7RLWnGMEGwaDh4Oh
NPAF2IvGuTnOnDKsvwTVjbgv7mFVufO5uJPHbZw5aLQ52Gddy1u91aG42RgWfPP/
enfZzGjzyO60UgY3bI4jaRxJgRwIJoChBYvt9dwzxoR64+8vwyICoDONSGGKmCc0
6HVd61aTo74uxQSr1ojMU8ac25+qXevGgg==
-----END CERTIFICATE-----
`
