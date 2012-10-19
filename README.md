<h4>ENCRYPTER</h4>
Encrypter uses Base64Coder class to do conversions in encryption and decryption.
   
Encrypter supports AES and DES cipher algorithms.
Is currently in ECB mode with NoPadding as padding.
Does CBC manually in encrypt and decrypt methods.

Strings must be in multiples of 64-bits or 128-bits for DES and AES, respectively.
<h4>BASE64CODER</h4>
Copyright 2003-2010 Christian d'Heureuse, Inventec Informatik AG, Zurich, Switzerland

www.source-code.biz, www.inventec.ch/chdh

This class is used to encode and decode data in Base64 format as described in RFC 1521.