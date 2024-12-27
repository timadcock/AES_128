package test;

import source.Utils;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test class for the Utils class
 * @author Tim Adcock
 */
class UtilsTest {

    @org.junit.jupiter.api.Test
    void text_to_hex() {
        BigInteger    tmp  = Utils.text_to_hex("Hello");
        assertEquals("96231036770457542450679237503772262400", tmp.toString());
    }

    @org.junit.jupiter.api.Test
    void hex_to_matrix() {
        BigInteger tmp = new BigInteger(
                "96231036770457542450679237503772262400");
        int[][] result = {{72, 101, 108, 108}, {111, 0, 0, 0}, {0, 0, 0, 0},
                          {0, 0, 0, 0}};
        assertArrayEquals(result, Utils.hex_to_matrix(tmp));
    }

    @org.junit.jupiter.api.Test
    void text_to_matrix() {
        StringBuilder test = new StringBuilder("Hello");
        BigInteger    hex  = Utils.text_to_hex(String.valueOf(test));
        assertEquals("96231036770457542450679237503772262400", hex.toString());
        int[][] mat = {{72, 101, 108, 108}, {111, 0, 0, 0}, {0, 0, 0, 0},
                       {0, 0, 0, 0}};
        assertArrayEquals(mat, Utils.hex_to_matrix(hex));
        assertArrayEquals(mat, Utils.text_to_matrix(String.valueOf(test)));
    }


}