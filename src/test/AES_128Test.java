package test;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import source.AES_128;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test class for the AES_128 class
 *
 * @author Tim Adcock
 */
class AES_128Test {

    String[] constants = {
            "c29dc284c3b3c39f0d36c2a3c2b3c2a906c284c38ec3be11c3ab73",
            "253ec3a40b16c3b20e5e3b06c28ac3956dc3a8c2b677",
            "54c28bc2abc39dc3b36b49157310043b77c2b425c28c"};

    @ParameterizedTest
    // Various keys to test for
    @CsvSource({"1234567890123456,0", "1234567890123456123456,0",
                "12345678901,1", "a,2"})
    void encrypt(String key, int index) {
        AES_128 aes = new AES_128(key);

        // WIll compare hex instead of the encoded bytes.
        String test = String.format("%x", new BigInteger(1, aes.encrypt(
                "Hello World!").getBytes()));

        assertEquals(constants[index], test);


    }

    @ParameterizedTest
    // Various keys to test for
    @CsvSource({"1234567890123456,0", "1234567890123456123456,0",
                "12345678901,1", "a,2"})
    void decrypt(String key, int index) {

        // Translate hex to string for bytes.
        String text = new String(HexFormat.of().parseHex(constants[index]));

        AES_128 aes  = new AES_128(key);
        String  test = aes.decrypt(text);
        assertEquals("Hello World!", test);
    }
}