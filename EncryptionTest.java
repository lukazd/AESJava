import java.io.FileNotFoundException;


public class EncryptionTest {
	public static void main(String [] args) {
		if (args.length < 4) {
			System.out.println("You must specify encryption or decryption (e or d), the mode of operation, the key, the input file, the output file, and optionally the iv");
			return;
		}
		long start = System.currentTimeMillis();
		try {
			if (args[1].equals("ecb")) {
				if (args[0].equals("d")) {
					ECB ecb = new ECB(args[4], args[3], args[2]);
					ecb.startDecryption();
				} else {
					ECB ecb = new ECB(args[3], args[4], args[2]);
					ecb.startEncryption();
				}
			} else {
				if (args[0].equals("d")) {
					CBC cbc = new CBC(args[4], args[3], args[2], args[5]);
					cbc.startDecryption();
				} else {
					CBC cbc = new CBC(args[3], args[4], args[2], args[5]);
					cbc.startEncryption();
				}
			}
			
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		long end = System.currentTimeMillis();
		System.out.println("Time of execution: " + (end - start) + " milliseconds");
	}
}
