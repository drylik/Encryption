package ru.novikov;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class RSATests {

    private static final byte[] data16Bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final String message31Bytes = "hello, cryptor, I have 31 Bytes";

    @Test
    public void encrypt16BytesRSATest() throws IOException {
        CipherAlg rsa = new RSA();
        ByteArrayInputStream data = new ByteArrayInputStream(RSATests.data16Bytes);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        rsa.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        rsa.decrypt(data, oldData);

        buffer = oldData.toByteArray();
        Assert.assertArrayEquals(RSATests.data16Bytes, buffer);
    }

    @Test
    public void encrypt31BytesStringRSATest() throws IOException {
        CipherAlg rsa = new RSA();
        InputStream data = IOUtils.toInputStream(RSATests.message31Bytes, StandardCharsets.UTF_8);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        rsa.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        rsa.decrypt(data, oldData);

        Assert.assertArrayEquals(RSATests.message31Bytes.getBytes(), oldData.toByteArray());
        Assert.assertEquals(RSATests.message31Bytes, oldData.toString());
    }
}
