package ru.novikov;

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MD5Tests {

    private static final String message16Bytes = "hello, cryptor!!";
    private static final String hashedMessage16Bytes = "BC868602E23E4292704AAA584B9E4341";
    private static final String message31Bytes = "hello, cryptor, I have 31 Bytes";
    private static final String hashedMessage31Bytes = "FD3D2895CAAA377591EFBA594D4CAD1D";

    @Test
    public void hash16BytesTest() throws IOException {
        MD5 md5 = new MD5();
        ByteArrayInputStream data = new ByteArrayInputStream(MD5Tests.message16Bytes.getBytes());
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        md5.computeMD5(data, newData);

        byte[] buffer = newData.toByteArray();
        String str = md5.toHexString(buffer);
        Assert.assertEquals(MD5Tests.hashedMessage16Bytes, str);
    }

    @Test
    public void hash31BytesTest() throws IOException {
        MD5 md5 = new MD5();
        ByteArrayInputStream data = new ByteArrayInputStream(MD5Tests.message31Bytes.getBytes());
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        md5.computeMD5(data, newData);

        byte[] buffer = newData.toByteArray();
        String str = md5.toHexString(buffer);
        Assert.assertEquals(MD5Tests.hashedMessage31Bytes, str);
    }
}
