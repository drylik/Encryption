package ru.novikov;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class RSATests {

    private static final byte[] data16Bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static final String message31Bytes = "hello, cryptor, I have 31 Bytes";

    private static final BigInteger n = new BigInteger("88053076553485916132103470938618270097248255839999611143397097542721280746766919667414981647286905586358751352852053442902667806818674474161795629626218601742363171807698465792903875964069892416276023195456536769709809717596596234866035816373841119288213210953520537052137988934133312888145476931669977736767");
    private static final BigInteger e = new BigInteger("5");
    private static final BigInteger d = new BigInteger("70442461242788732905682776750894616077798604671999688914717678034177024597413535733931985317829524469087001082281642754322134245454939579329436503700974865688020459745514676708141267406733090396691301633873208268281122775970209127942974547122412846504379326501383763008468042848096753153502854989808930862125");

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

    @Test
    public void encrWithKnownKey() throws Exception {
        RSA rsa = new RSA(e, n, "privateKey.dat");
        Assert.assertEquals(d, rsa.getD());
    }
}
