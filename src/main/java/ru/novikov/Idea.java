package ru.novikov;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * IDEA (International Data Encryption Algorithm).
 */
public class Idea implements CipherAlg {

    private static final int rounds = 8;
    //массив подключей
    private final int[] subKey;

    public Idea(InputStream key) throws IOException {
        subKey = generateSubKey(key);
    }

    /**
     * Шифрует или расшифровывает данные.
     * Если количество байт данных не кратно 8, дополняем его согласно ANSI X.923.
     */
    @Override
    public void encrypt(InputStream in, OutputStream out) throws IOException {
        int dataSize = in.available();
        byte[] buffer = new byte[8];
        for (int i = 0; i < dataSize/8 && in.read(buffer) != -1; i++) {
            buffer = crypt(buffer, subKey);
            out.write(buffer);
        }
        if (dataSize % 8 != 0) {
            in.read(buffer);
            buffer = addition(buffer, (dataSize / 8 + 1) * 8 - dataSize);
            out.write(crypt(buffer, subKey));
        }
    }

    @Override
    public void decrypt(InputStream in, OutputStream out) throws IOException {
        int[] decryptionKey = invertSubKey(subKey);
        int dataSize = in.available();
        byte[] buffer = new byte[8];
        boolean added = false;
        for (int i = 0; i < dataSize/8 && in.read(buffer) != -1; i++) {
            buffer = crypt(buffer, decryptionKey);
            if (i == dataSize/8 - 1 && buffer[buffer.length - 1] < 8) {
                added = true;
                for (int j = 0; j < buffer[buffer.length - 1] - 1; j++) {
                    if (buffer[buffer.length - 2 - j] != 0) {
                        added = false;
                        break;
                    }
                }
            } else {
                out.write(buffer);
            }
        }
        if (added) {
            byte[] resultData = new byte[buffer.length - buffer[buffer.length - 1]];
            System.arraycopy(buffer, 0, resultData, 0, resultData.length);
            out.write(resultData);
        }
    }

    /**
     * Шифрует или расшифровывает 8 байтный блок данных.
     */
    private byte[] crypt(byte[] data, int[] subKey) {

        byte[] newData = new byte[8];

        int D1 = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
        int D2 = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        int D3 = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
        int D4 = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        //
        int p = 0;
        for (int round = 0; round < rounds; round++) {
            int A = mul(D1, subKey[p++]);
            int B = add(D2, subKey[p++]);
            int C = add(D3, subKey[p++]);
            int D = mul(D4, subKey[p++]);
            //
            int E1 = mul(A ^ C, subKey[p++]);
            int F1 = add(B ^ D, E1);
            int F2 = mul(F1, subKey[p++]);
            int E2 = add(E1, F2);
            //
            D1 = A ^ F2;
            D2 = C ^ F2;
            D3 = B ^ E2;
            D4 = D ^ E2; }
        //
        int res1 = mul(D1, subKey[p++]);
        int res2 = add(D3, subKey[p++]);
        int res3 = add(D2, subKey[p++]);
        int res4 = mul(D4, subKey[p]);
        //
        newData[0] = (byte)(res1 >> 8);
        newData[1] = (byte)res1;
        newData[2] = (byte)(res2 >> 8);
        newData[3] = (byte)res2;
        newData[4] = (byte)(res3 >> 8);
        newData[5] = (byte)res3;
        newData[6] = (byte)(res4 >> 8);
        newData[7] = (byte)res4;

        return newData;
    }

    /**
     * Дополнение открытых данных согласно ANSI X.923.
     */
    private static byte[] addition(byte[] data, int n) {
        data[data.length - 1] = (byte) n;
        for (int i = 1; i < n; i++) {
            data[data.length - 1 - i] = (byte) 0;
        }
        return data;
    }

    /**
     * Сложение по модулю 2 в 16 степени.
     * Результат в диапазоне от 0 до 0xFFFF (65535).
     */
    private static int add (int a, int b) {
        return (a + b) & 0xFFFF;
    }

    /**
     * Сложение по модулю 2 в 16 степени с инвертированием (-K).
     * Результат в диапазоне от 0 до 0xFFFF (65535).
     */
    private static int addInv (int x) {
        return (0x10000 - x) & 0xFFFF;
    }

    /**
     * Умножение по модулю 2 в 16 степени + 1.
     * Результат в диапазоне от 0 до 0xFFFF (65535).
     */
    private static int mul (int a, int b ) {
        long r = (long)a * b;
        if (r != 0) {
            return (int)(r % 0x10001) & 0xFFFF;
        }
        else {
            return (1 - a - b) & 0xFFFF;
        }
    }

    /**
     * Умножение по модулю 2 в 16 степени + 1 с инвертированием (1/K).
     * Результат в диапазоне от 0 до 0xFFFF (65535).
     * Для всех значений x верно: mul(x, mulInv(x)) == 1.
     */
    private static int mulInv (int x) {
        if (x <= 1) {
            return x;
        }
        int y = 0x10001;
        int t0 = 1;
        int t1 = 0;
        while (true) {
            t1 += y / x * t0;
            y %= x;
            if (y == 1) {
                return 0x10001 - t1;
            }
            t0 += x / y * t1;
            x %= y;
            if (x == 1) {
                return t0;
            }
        }
    }

    private static int[] invertSubKey (int[] key) {
        int[] invKey = new int[key.length];
        int p = 0;
        int i = rounds * 6;
        invKey[i] = mulInv(key[p++]);
        invKey[i + 1] = addInv(key[p++]);
        invKey[i + 2] = addInv(key[p++]);
        invKey[i + 3] = mulInv(key[p++]);
        for (int r = rounds - 1; r >= 0; r--) {
            i = r * 6;
            int m = (r > 0) ? 2 : 1;
            int n = (r > 0) ? 1 : 2;
            invKey[i + 4] = key[p++];
            invKey[i + 5] = key[p++];
            invKey[i] = mulInv(key[p++]);
            invKey[i + m] = addInv(key[p++]);
            invKey[i + n] = addInv(key[p++]);
            invKey[i + 3] = mulInv(key[p++]);
        }
        return invKey;
    }

    private static int[] generateSubKey(InputStream userKey) throws IOException {
        int keySize = userKey.available();
        if (keySize != 16) {
            throw new IllegalArgumentException();
        }
        byte[] userKeyByte = new byte[keySize];
        userKey.read(userKeyByte);
        int[] key = new int[rounds * 6 + 4];
        //первые 8 подключей
        for (int i = 0; i < keySize / 2; i++) {
            key[i] = ((userKeyByte[2 * i] & 0xFF) << 8) | (userKeyByte[2 * i + 1] & 0xFF);
        }
        for (int i = userKeyByte.length / 2; i < key.length; i++) {
            key[i] = ((key[((i + 1) % 8 != 0) ? i - 7 : i - 15] << 9) | (key[((i + 2) % 8 < 2) ? i - 14 : i - 6] >> 7)) & 0xFFFF;
        }
        userKey.reset();
        return key;
    }
}

