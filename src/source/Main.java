package source;

public class Main {
    public static void main(String[] args) {

        AES_128 aes = new AES_128("1234567890123456");
        //System.out.println(aes);
        aes.encrypt("Hello World!");
        //System.out.println(enc);
    }


}