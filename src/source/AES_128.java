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

    public String encrypt(String text) {
        int[][] plain_text = Utils.text_to_matrix(text);
        int[][] encrypted_matrix = this.addRoundKey(plain_text,
                                                    this.round_keys[0]
        );

        for (int i = 1; i < 10; i++) {
            encrypted_matrix = this.round_encrypt(encrypted_matrix,
                                                  this.round_keys[i]
            );
        }

        encrypted_matrix = this.subbyte(encrypted_matrix);
        encrypted_matrix = this.shift_rows(encrypted_matrix);
        encrypted_matrix = this.addRoundKey(encrypted_matrix,
                                            this.round_keys[9]
        );

        return Utils.matrix_to_string(encrypted_matrix);
    }


    /**
     * Decrypts a cipher texts.
     *
     * @param cypher_text Text to decrypt.
     * @return Decrypted text.
     */
    public String decrypt(String cypher_text) {
        int[][] decrypted_matrix = Utils.text_to_matrix(cypher_text);
        decrypted_matrix = this.addRoundKey(decrypted_matrix,
                                            this.round_keys[9]
        );

        decrypted_matrix = this.inverse_shift_rows(decrypted_matrix);
        decrypted_matrix = this.inverse_subbyte(decrypted_matrix);

        for (int i = 9; i > 0; i--) {
            decrypted_matrix = this.round_decrypt(decrypted_matrix,
                                                  this.round_keys[i]
            );
        }

        decrypted_matrix = this.addRoundKey(decrypted_matrix,
                                            this.round_keys[0]
        );

        return Utils.matrix_to_string(decrypted_matrix);
    }

    /**
     * Performs the steps needed to decrypt a single round.
     *
     * @param decryptedMatrix Current matrix being worked on.
     * @param roundKey        Key for this round.
     * @return Decrypted round matrix.
     */
    private int[][] round_decrypt(int[][] decryptedMatrix, int[][] roundKey) {

        decryptedMatrix = this.addRoundKey(decryptedMatrix, roundKey);
        decryptedMatrix = this.inverse_mix_columns(decryptedMatrix);
        decryptedMatrix = this.inverse_shift_rows(decryptedMatrix);

        return this.inverse_subbyte(decryptedMatrix);
    }

    /**
     * Inverse of mix_columns.
     *
     * @param decryptedMatrix Matrix being mixed.
     * @return Mixed matrix.
     */
    private int[][] inverse_mix_columns(int[][] decryptedMatrix) {
        int[][] output = new int[4][4];
        for (int i = 0; i < 4; i++) {
            int a = this.xtime(
                    this.xtime(decryptedMatrix[i][0] ^ decryptedMatrix[i][2]));
            int b = this.xtime(
                    this.xtime(decryptedMatrix[i][1] ^ decryptedMatrix[i][3]));
            output[i][0] = decryptedMatrix[i][0] ^ a;
            output[i][1] = decryptedMatrix[i][1] ^ b;
            output[i][2] = decryptedMatrix[i][2] ^ a;
            output[i][3] = decryptedMatrix[i][3] ^ b;
        }
        return this.mix_columns(output);
    }


    /**
     * Performs the steps needed to encrypt a single round.
     *
     * @param encryptedMatrix Matrix to be encrypted.
     * @param key             Key for this round.
     * @return Encrypted matrix.
     */
    private int[][] round_encrypt(int[][] encryptedMatrix, int[][] key) {

        encryptedMatrix = this.subbyte(encryptedMatrix);
        encryptedMatrix = this.shift_rows(encryptedMatrix);
        encryptedMatrix = this.mix_columns(encryptedMatrix);

        return this.addRoundKey(encryptedMatrix, key);

    }

    /**
     * The procedure to mix the columns of the plaintext.
     *
     * @param m Matrix to be mixed.
     * @return Mixed Matrix.
     */
    private int[][] mix_columns(int[][] m) {
        for (int i = 0; i < 4; i++) {
            m[i] = this.mix_single_column(m[i]);
        }
        return m;
    }

    /**
     * Helper function to mix a single column
     *
     * @param c Column to be mixed.
     * @return Mixed column.
     */
    private int[] mix_single_column(int[] c) {
        int[] new_column = new int[4];
        int   a          = c[0] ^ c[1] ^ c[2] ^ c[3];
        int   z          = c[0];
        new_column[0] = c[0] ^ a ^ this.xtime(c[0] ^ c[1]);
        new_column[1] = c[1] ^ a ^ this.xtime(c[1] ^ c[2]);
        new_column[2] = c[2] ^ a ^ this.xtime(c[2] ^ c[3]);
        new_column[3] = c[3] ^ a ^ this.xtime(c[3] ^ z);
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
    private int[][] addRoundKey(int[][] plainText, int[][] k) {

        int[][] output = plainText.clone();

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = output[i][j] ^ k[i][j];
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
        }
    }

    /**
     * Function to make a single rounds key.
     *
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
        int[][] output = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = Utils.SUBBYTE[e[i][j]];

            }
        }
        return output;
    }

    /**
     * Inverted function for subbyte.
     *
     * @param d Matrix to be converted.
     * @return Converted matrix.
     */
    private int[][] inverse_subbyte(int[][] d) {
        int[][] output = new int[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[i][j] = Utils.INVERSE_SUBBYTE[d[i][j]];
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

        output[0][1] = e[1][1];
        output[1][1] = e[2][1];
        output[2][1] = e[3][1];
        output[3][1] = e[0][1];

        output[0][2] = e[2][2];
        output[1][2] = e[3][2];
        output[2][2] = e[0][2];
        output[3][2] = e[1][2];

        output[0][3] = e[3][3];
        output[1][3] = e[0][3];
        output[2][3] = e[1][3];
        output[3][3] = e[2][3];

        output[0][0] = e[0][0];
        output[1][0] = e[1][0];
        output[2][0] = e[2][0];
        output[3][0] = e[3][0];


        return output;
    }

    /**
     * Inverted shift_rows
     *
     * @param d Matrix to be shifted.
     * @return Shifted matrix.
     */
    private int[][] inverse_shift_rows(int[][] d) {
        int[][] output = new int[4][4];

        output[0][1] = d[3][1];
        output[1][1] = d[0][1];
        output[2][1] = d[1][1];
        output[3][1] = d[2][1];

        output[0][2] = d[2][2];
        output[1][2] = d[3][2];
        output[2][2] = d[0][2];
        output[3][2] = d[1][2];

        output[0][3] = d[1][3];
        output[1][3] = d[2][3];
        output[2][3] = d[3][3];
        output[3][3] = d[0][3];

        output[0][0] = d[0][0];
        output[1][0] = d[1][0];
        output[2][0] = d[2][0];
        output[3][0] = d[3][0];


        return output;
    }
}
