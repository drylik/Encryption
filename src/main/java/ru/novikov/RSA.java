package ru.novikov;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA implements CipherAlg {
    private static final String DEFAULT_FILE_NAME = "private.dat";

    /**
     * {e, n} - public key
     * {d, n} - private key
     */
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }

    public String getPublicKey() {
        return e.toString() + " " + n.toString();
    }

    /**
     * default length of p and q
     */
    private int bitLength = 1024;

    public RSA() throws IOException {
        generateKeys();
    }

    public BigInteger getD() {
        return d;
    }

    /**
     * for someone's else public and private keys
     */
    public RSA(BigInteger e, BigInteger n, String filename) throws Exception {
        this.e = e;
        this.n = n;
        File file = new File(filename);
        if (!file.exists()) {
            throw new Exception("No private key found");
        }
        FileInputStream fin = new FileInputStream(file);
        byte[] buffer = new byte[fin.available()];
        fin.read(buffer);
        if (!n.equals(new BigInteger(new String(buffer).split(" ")[1]))) {
            throw new Exception("Private and public keys don't fit each other");
        }
        d = new BigInteger(new String(buffer).split(" ")[0]);
        fin.close();
    }

    public RSA(int bitLength) throws IOException {
        this.bitLength = bitLength;
        generateKeys();
    }

    private void generateKeys() throws IOException {
        SecureRandom sr = new SecureRandom();
        BigInteger p = new BigInteger(bitLength / 2, 100, sr);
        BigInteger q = new BigInteger(bitLength / 2, 100, sr);
        n = p.multiply(q);
        //Euler's function
        BigInteger f = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (f.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(f);
        //saving private key
        File file = new File(DEFAULT_FILE_NAME);
        if (file.exists()) {
            file.delete();
        }
        file.createNewFile();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(d.toByteArray());
        fos.write(0);
        fos.write(n.toByteArray());
        fos.close();
    }

    @Override
    public void encrypt(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[in.available()];
        in.read(buffer);
        BigInteger encryptedData = new BigInteger(buffer).modPow(e, n);
        out.write(encryptedData.toByteArray());
    }

    @Override
    public void decrypt(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[in.available()];
        in.read(buffer);
        BigInteger decryptedData = new BigInteger(buffer).modPow(d, n);
        out.write(decryptedData.toByteArray());
    }
}
