package ru.novikov;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class IDEATests {

    private static final byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final byte[] data16Bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final byte[] encryptedData16Bytes = {-65, -109, 54, 77, 63, -111, -84, 65, 120, 45, -69, 120, 14, 63, -93, 89};
    private static final byte[] data14Bytes = {14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    private static final String stringKey = "8522123654789456";
    private static final String message16Bytes = "hello, cryptor!!";
    private static final byte[] encryptedString16Bytes = {86, -42, 45, 127, 101, -75, -34, 8, 120, -77, -53, -71, 106, 46, 75, 101};
    private static final String message31Bytes = "hello, cryptor, I have 31 Bytes";

    @Test
    public void encrypt16BytesIdeaTest() throws IOException {
        ByteArrayInputStream key = new ByteArrayInputStream(IDEATests.key);
        CipherAlg idea = new Idea(key);
        ByteArrayInputStream data = new ByteArrayInputStream(IDEATests.data16Bytes);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        idea.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        Assert.assertArrayEquals(IDEATests.encryptedData16Bytes, buffer);
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        idea.decrypt(data, oldData);

        buffer = oldData.toByteArray();
        Assert.assertArrayEquals(IDEATests.data16Bytes, buffer);
    }

    @Test
    public void encrypt14BytesIdeaTest() throws IOException {
        ByteArrayInputStream key = new ByteArrayInputStream(IDEATests.key);
        CipherAlg idea = new Idea(key);
        ByteArrayInputStream data = new ByteArrayInputStream(IDEATests.data14Bytes);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        idea.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        idea.decrypt(data, oldData);

        buffer = oldData.toByteArray();
        Assert.assertArrayEquals(IDEATests.data14Bytes, buffer);
    }

    @Test
    public void encrypt16BytesStringIdeaTest() throws IOException {
        InputStream key = IOUtils.toInputStream(stringKey, StandardCharsets.UTF_8);
        CipherAlg idea = new Idea(key);
        InputStream data = IOUtils.toInputStream(IDEATests.message16Bytes, StandardCharsets.UTF_8);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        idea.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        Assert.assertArrayEquals(IDEATests.encryptedString16Bytes, buffer);
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        idea.decrypt(data, oldData);

        Assert.assertArrayEquals(IDEATests.message16Bytes.getBytes(), oldData.toByteArray());
        Assert.assertEquals(IDEATests.message16Bytes, oldData.toString());
    }

    @Test
    public void encrypt31BytesStringIdeaTest() throws IOException {
        InputStream key = IOUtils.toInputStream(stringKey, StandardCharsets.UTF_8);
        CipherAlg idea = new Idea(key);
        InputStream data = IOUtils.toInputStream(IDEATests.message31Bytes, StandardCharsets.UTF_8);
        ByteArrayOutputStream newData = new ByteArrayOutputStream();
        idea.encrypt(data, newData);

        byte[] buffer = newData.toByteArray();
        data = new ByteArrayInputStream(buffer);

        ByteArrayOutputStream oldData = new ByteArrayOutputStream();
        idea.decrypt(data, oldData);

        Assert.assertArrayEquals(IDEATests.message31Bytes.getBytes(), oldData.toByteArray());
        Assert.assertEquals(IDEATests.message31Bytes, oldData.toString());
    }
}
