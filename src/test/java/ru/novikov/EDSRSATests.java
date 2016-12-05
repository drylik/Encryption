package ru.novikov;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class EDSRSATests {

    private static final byte[] data16Bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final String message31Bytes = "hello, cryptor, I have 31 Bytes";

    @Test
    public void signData16Bytes() throws Exception {
        EDSRSA edsrsa = new EDSRSA();
        ByteArrayInputStream data = new ByteArrayInputStream(EDSRSATests.data16Bytes);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        edsrsa.sign(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        edsrsa.getPrototype(data, oldData);

        buffer = oldData.toByteArray();
        Assert.assertArrayEquals(EDSRSATests.data16Bytes, buffer);
    }

    @Test
    public void signMessage31Bytes() throws Exception {
        EDSRSA edsrsa = new EDSRSA();
        ByteArrayInputStream data = new ByteArrayInputStream(EDSRSATests.message31Bytes.getBytes());
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        edsrsa.sign(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        edsrsa.getPrototype(data, oldData);

        buffer = oldData.toByteArray();
        Assert.assertEquals(EDSRSATests.message31Bytes, new String(buffer));
    }
}
