package source;

/**
 * Implementation of the AES_128 algorithm.
 *
 * @author Tim Adcock
 */
public class AES_128 {

    private final int[][][] round_keys  = new int[10][4][4];
    private       int[][]   private_key = new int[4][4];


    /**
     * Constructor for AES_128
     *
     * @param private_key Private key to be used.
     */
    public AES_128(String private_key) {
        this.private_key   = Utils.text_to_matrix(private_key);
        this.round_keys[0] = this.private_key.clone();

        this.make_round_keys();
    }

    public void encrypt(String text) {
        int[][] plain_text       = Utils.text_to_matrix(text);
        int[][] encrypted_matrix = this.addRoundKey(plain_text, 0);

        for (int i = 1; i < 10; i++) {
            encrypted_matrix = this.round_encrypt(encrypted_matrix, i);
        }

        encrypted_matrix = this.subbyte(encrypted_matrix);
        encrypted_matrix = this.shift_rows(encrypted_matrix);
        encrypted_matrix = this.addRoundKey(encrypted_matrix, 9);

        for (int i = 0; i < encrypted_matrix.length; i++) {
            for (int j = 0; j < encrypted_matrix[i].length; j++) {
                System.out.print(encrypted_matrix[i][j] + " ");
            }
            System.out.println();
        }


        //return Utils.matrix_to_string(encrypted_matrix);
    }


//    public String decrypt(String cypher_text) {
//        int[][] decrypted_matrix = Utils.text_to_matrix(cypher_text);
//        decrypted_matrix = this.addRoundKey(decrypted_matrix, 9);
//        decrypted_matrix = this.inverse_shift_rows(decrypted_matrix);
//        decrypted_matrix = this.inverse_subbyte(decrypted_matrix);
//
//        for (int i = 9; i > 0; i--) {
//            decrypted_matrix = this.round_decrypt(decrypted_matrix,i);
//        }
//
//    }

    private int[][] round_encrypt(int[][] encryptedMatrix, int i) {

        int[][] m = this.round_keys[i].clone();

        m = this.subbyte(m);
        m = this.shift_rows(m);
        m = this.mix_columns(m);
        m = this.addRoundKey(m, i);

        return m;

    }

    private int[][] mix_columns(int[][] m) {
        for (int i = 0; i < 4; i++) {
            m[i] = this.mix_single_column(m[i]);
        }
        return m;
    }

    private int[] mix_single_column(int[] c) {
        int[] new_column = new int[4];
        int a = c[0] ^ c[1] ^ c[2] ^ c[3];
        int z = c[0];
        new_column[0] ^= a ^ this.xtime(c[0] ^ c[1]);
        new_column[1] ^= a ^ this.xtime(c[1] ^ c[2]);
        new_column[2] ^= a ^ this.xtime(c[2] ^ c[3]);
        new_column[3] ^= a ^ this.xtime(c[3] ^ z);
        return new_column;
    }

    /**
     * A special function used during the mix a columns part of the round, it helps with mixing.
     *
     * @param m The current plaintext column that will used.
     * @return The plaintext column after the operation was completed.
     */
    private int xtime(int m) {

        if ((m & 0x80) != 0) {
            return ((m << 1) ^ 0x1B) & 0xFF;
        } else {
            return (m << 1);
        }
    }


    /**
     * FUnction to add a round key to a plaintext matrix.
     *
     * @param plainText Plant text matrix.
     * @param k         Index of round key to use.
     * @return Matrix with round key added.
     */
    private int[][] addRoundKey(int[][] plainText, int k) {

        int[][] output = plainText.clone();

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = output[i][j] ^ this.round_keys[k][i][j];
            }
        }
        return output;
    }

    /**
     * Function to make each round keys for encryption.
     */
    private void make_round_keys() {

        // First round is always the private key
        for (int i = 1; i < 10; i++) {
            this.round_keys[i] = this.make_round(i);
            // System.out.println(this.matrix_to_string(this.round_keys[i]));
        }
    }

    /**
     * @param i Round number to retrieve previous round key.
     * @return Round key at round i
     */
    private int[][] make_round(int i) {

        int[][] output = new int[4][4];

        int[][] m = round_keys[i - 1];


        int[] c3 = {m[0][3], m[1][3], m[2][3], m[3][3]};

        int[] rw = {c3[1], c3[2], c3[3], c3[0]};
        int[] sb = {Utils.SUBBYTE[rw[0]], Utils.SUBBYTE[rw[1]],
                    Utils.SUBBYTE[rw[2]], Utils.SUBBYTE[rw[3]]};

        int[] ck0 = {m[0][0] ^ sb[0] ^ Utils.RCON[i], m[1][0] ^ sb[1],
                     m[2][0] ^ sb[2], m[3][0] ^ sb[3]};

        int[] ck1 = {ck0[0] ^ m[0][1], ck0[1] ^ m[1][1], ck0[2] ^ m[2][1],
                     ck0[3] ^ m[3][1]};

        int[] ck2 = {ck1[0] ^ m[0][2], ck1[1] ^ m[1][2], ck1[2] ^ m[2][2],
                     ck1[3] ^ m[3][2]};

        int[] ck3 = {ck2[0] ^ m[0][3], ck2[1] ^ m[1][3], ck2[2] ^ m[2][3],
                     ck2[3] ^ m[3][3]};

        for (int j = 0; j < 4; j++) {
            output[j][0] = ck0[j];
            output[j][1] = ck1[j];
            output[j][2] = ck2[j];
            output[j][3] = ck3[j];

        }
        return output;
    }

    /**
     * Function to return a matrix fo characters with their correlated
     * subbyte value.
     *
     * @param e Matrix to convert.
     * @return Converted matrix
     */
    private int[][] subbyte(int[][] e) {
        int[][] output = e.clone();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[j][i] = Utils.SUBBYTE[e[i][j]];
            }
        }
        return output;
    }

    private int[][] inverse_subbyte(int[][] d) {
        int[][] output = new int[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[j][i] = Utils.INVERSE_SUBBYTE[d[i][j]];
            }
        }
        return output;
    }

    /**
     * Shift rows of the current block matrix.
     *
     * @param e Matrix to shift.
     * @return Shifted matrix.
     */
    private int[][] shift_rows(int[][] e) {
        int[][] output = new int[4][4];

        for (int i = 1; i < 4; i++) {
            output[0][i] = e[i][i];
            output[1][i] = e[(i + 1) % 4][i];
            output[2][i] = e[(i + 2) % 4][i];
            output[3][i] = e[(i + 3) % 4][i];
        }
        return output;
    }

    private int[][] inverse_shift_rows(int[][] d) {
        int[][] output = new int[4][4];

        for (int i = 1; i < 4; i++) {
            output[0][i] = d[4 - i][i];
        }

        output[1][1] = d[0][1];
        output[1][2] = d[3][1];
        output[1][3] = d[2][1];

        output[2][1] = d[1][1];
        output[2][2] = d[0][1];
        output[2][3] = d[3][1];

        output[3][1] = d[2][1];
        output[3][2] = d[1][1];
        output[3][3] = d[0][1];


        return output;
    }


    public String toString() {
        return this.matrix_to_string(this.private_key);
    }

    private String matrix_to_string(int[][] input) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < input.length; i++) {
            for (int j = 0; j < input[i].length; j++) {
                sb.append(input[i][j] + " ");
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
