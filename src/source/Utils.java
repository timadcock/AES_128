package source;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Utility class for constants and utility functions.
 *
 * @author Tim Adcock
 */
public class Utils {

    /**
     * Chart used for the Sub Byte method
     */
    static final public int[] SUBBYTE = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B,
                                         0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
                                         0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
                                         0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
                                         0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
                                         0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
                                         0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5,
                                         0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                                         0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96,
                                         0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
                                         0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83,
                                         0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
                                         0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3,
                                         0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
                                         0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
                                         0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                                         0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D,
                                         0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
                                         0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3,
                                         0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
                                         0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF,
                                         0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
                                         0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7,
                                         0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                                         0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
                                         0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
                                         0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32,
                                         0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
                                         0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95,
                                         0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
                                         0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56,
                                         0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                                         0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
                                         0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
                                         0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
                                         0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
                                         0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1,
                                         0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
                                         0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
                                         0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                                         0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6,
                                         0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
                                         0xB0, 0x54, 0xBB, 0x16};

    /**
     * This is used for the inverse Sub Byte method
     */
    public static final int[] INVERSE_SUBBYTE = {0x52, 0x09, 0x6A, 0xD5, 0x30,
                                                 0x36, 0xA5, 0x38, 0xBF, 0x40,
                                                 0xA3, 0x9E, 0x81, 0xF3, 0xD7,
                                                 0xFB, 0x7C, 0xE3, 0x39, 0x82,
                                                 0x9B, 0x2F, 0xFF, 0x87, 0x34,
                                                 0x8E, 0x43, 0x44, 0xC4, 0xDE,
                                                 0xE9, 0xCB, 0x54, 0x7B, 0x94,
                                                 0x32, 0xA6, 0xC2, 0x23, 0x3D,
                                                 0xEE, 0x4C, 0x95, 0x0B, 0x42,
                                                 0xFA, 0xC3, 0x4E, 0x08, 0x2E,
                                                 0xA1, 0x66, 0x28, 0xD9, 0x24,
                                                 0xB2, 0x76, 0x5B, 0xA2, 0x49,
                                                 0x6D, 0x8B, 0xD1, 0x25, 0x72,
                                                 0xF8, 0xF6, 0x64, 0x86, 0x68,
                                                 0x98, 0x16, 0xD4, 0xA4, 0x5C,
                                                 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                                                 0x6C, 0x70, 0x48, 0x50, 0xFD,
                                                 0xED, 0xB9, 0xDA, 0x5E, 0x15,
                                                 0x46, 0x57, 0xA7, 0x8D, 0x9D,
                                                 0x84, 0x90, 0xD8, 0xAB, 0x00,
                                                 0x8C, 0xBC, 0xD3, 0x0A, 0xF7,
                                                 0xE4, 0x58, 0x05, 0xB8, 0xB3,
                                                 0x45, 0x06, 0xD0, 0x2C, 0x1E,
                                                 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
                                                 0xC1, 0xAF, 0xBD, 0x03, 0x01,
                                                 0x13, 0x8A, 0x6B, 0x3A, 0x91,
                                                 0x11, 0x41, 0x4F, 0x67, 0xDC,
                                                 0xEA, 0x97, 0xF2, 0xCF, 0xCE,
                                                 0xF0, 0xB4, 0xE6, 0x73, 0x96,
                                                 0xAC, 0x74, 0x22, 0xE7, 0xAD,
                                                 0x35, 0x85, 0xE2, 0xF9, 0x37,
                                                 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                                                 0x47, 0xF1, 0x1A, 0x71, 0x1D,
                                                 0x29, 0xC5, 0x89, 0x6F, 0xB7,
                                                 0x62, 0x0E, 0xAA, 0x18, 0xBE,
                                                 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
                                                 0xC6, 0xD2, 0x79, 0x20, 0x9A,
                                                 0xDB, 0xC0, 0xFE, 0x78, 0xCD,
                                                 0x5A, 0xF4, 0x1F, 0xDD, 0xA8,
                                                 0x33, 0x88, 0x07, 0xC7, 0x31,
                                                 0xB1, 0x12, 0x10, 0x59, 0x27,
                                                 0x80, 0xEC, 0x5F, 0x60, 0x51,
                                                 0x7F, 0xA9, 0x19, 0xB5, 0x4A,
                                                 0x0D, 0x2D, 0xE5, 0x7A, 0x9F,
                                                 0x93, 0xC9, 0x9C, 0xEF, 0xA0,
                                                 0xE0, 0x3B, 0x4D, 0xAE, 0x2A,
                                                 0xF5, 0xB0, 0xC8, 0xEB, 0xBB,
                                                 0x3C, 0x83, 0x53, 0x99, 0x61,
                                                 0x17, 0x2B, 0x04, 0x7E, 0xBA,
                                                 0x77, 0xD6, 0x26, 0xE1, 0x69,
                                                 0x14, 0x63, 0x55, 0x21, 0x0C,
                                                 0x7D};

    /**
     * This chart is used for the Rcon method
     */
    public static final int[] RCON = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                                      0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x000,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x000, 0x00, 0x00};

    /**
     * Utility function to convert a string into a hexadecimal number
     * representing the string. WIll extend if greater than 16 or cut off if
     * less than 16.
     *
     * @param input_text Text to convert into a hexadecimal string.
     * @return Converted hexadecimal string
     */
    @Deprecated
    public static BigInteger text_to_hex(String input_text) {

        BigInteger    output      = BigInteger.valueOf(0);
        StringBuilder padded_text = new StringBuilder(input_text);

        if (padded_text.length() < 16) {
            padded_text.append("\0".repeat(16 - padded_text.length()));
        }

        for (int i = 0; i < 16; i++) {
            output = output.shiftLeft(8);
            int tmp = padded_text.charAt(i);
            output = output.or(BigInteger.valueOf(tmp));
        }
        return output;


    }

    /**
     * Utility function to convert a hexadecimal representation of a string
     * into a 4x4 matrix of the original characters of the string. Will cut
     * off if greater than 16 characters in size.
     *
     * @param hex_number Hexadecimal number to convert into a matrix
     * @return Matrix of characters
     */
    @Deprecated
    public static int[][] hex_to_matrix(BigInteger hex_number) {
        int[][]    output = new int[4][4];
        BigInteger tmp    = hex_number;


        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                BigInteger shift = tmp.shiftRight(j * 8);
                BigInteger anded = shift.and(BigInteger.valueOf(0xff));
                int        cell  = anded.intValue();
                output[4 - i - 1][4 - j - 1] = cell;
            }
            tmp = tmp.shiftRight(32);
        }


        return output;
    }

    /**
     * Utility function to convert a string input into a 4x4 matrix. This
     * will cut off more than 16 characters or extend if less than 16.
     *
     * @param input_text Text to convert into a matrix
     * @return 4x4 matrix of the text
     */
    public static int[][] text_to_matrix(String input_text) {
        int[][] output = new int[4][4];

        StringBuilder padded_text = new StringBuilder(input_text);
        if (padded_text.length() < 16) {
            padded_text.append("\0".repeat(16 - padded_text.length()));
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = padded_text.charAt(j + (i * 4));
            }
        }

        return output;
    }

    /**
     * Utility function to read data from file into StringBuilder object.
     *
     * @param input_file File path to read from.
     * @return StringBuilder of the content of the file.
     */
    public static StringBuilder read_file(String input_file) {
        StringBuilder output;
        try {
            BufferedReader br = new BufferedReader(
                    new FileReader(String.valueOf(input_file)));
            StringBuilder sb   = new StringBuilder();
            String        line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            output = new StringBuilder(sb.toString());
            br.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return output;

    }

    /**
     * Utility file to write string data to a file.
     *
     * @param data        String data to write out.
     * @param output_file File path to write to.
     */
    public static void write_to_file(String data, String output_file) {

        try {
            FileWriter br = new FileWriter(String.valueOf(output_file));
            br.write(data);

            br.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    public static String matrix_to_string(int[][] encryptedMatrix) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < encryptedMatrix.length; i++) {
            for (int j = 0; j < encryptedMatrix[0].length; j++) {
                output.append((char) encryptedMatrix[i][j]);
            }
        }
        return output.toString();
    }
}
