package ru.novikov;

import java.io.*;
import java.math.BigInteger;

public class EDSRSA {

    private static final String DEFAULT_FILE_NAME = "private.dat";
    private BigInteger e;
    private BigInteger n;
    private BigInteger d;

    public EDSRSA() throws Exception {
        RSA rsa = new RSA();
        e = rsa.getE();
        n = rsa.getN();
        d = rsa.getD();
    }

    public void sign(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[in.available()];
        in.read(buffer);
        BigInteger signedData = new BigInteger(buffer).modPow(d, n);
        out.write(signedData.toByteArray());
    }

    public void getPrototype(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[in.available()];
        in.read(buffer);
        BigInteger prototypeData = new BigInteger(buffer).modPow(e, n);
        out.write(prototypeData.toByteArray());
    }
}
