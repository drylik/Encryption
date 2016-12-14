package ru.novikov;

import java.io.*;
import java.math.BigInteger;

public class EDSRSA extends RSA {

    public EDSRSA() throws Exception {
        super();
    }

    public EDSRSA(BigInteger e, BigInteger n, String filename) throws Exception {
        super(e, n, filename);
    }

    public EDSRSA(String filename) throws IOException {
        super(filename);
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
