package ru.novikov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface CipherAlg {
    public void encrypt(InputStream in, OutputStream out) throws IOException;
    public void decrypt(InputStream in, OutputStream out) throws IOException;
}
