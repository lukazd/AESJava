import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;


public class CBC extends ModeOfOperation {

	private byte[] iv = new byte[16];
	private byte[] mixBlock = new byte[16];
	
	public CBC(String inputFileName, String outputFileName, String key, String iv) throws FileNotFoundException {
		super(inputFileName, outputFileName, key);
		this.iv = DatatypeConverter.parseHexBinary(iv);
	}

	@Override
	public void startEncryption() {
		mixBlock = Arrays.copyOf(iv, iv.length);
		while(readNextBlock()) {
			
			// add the iv or previous ciphertext
			for(int i = 0; i < 16; i++) {
				block[i] = (byte) ((block[i] & 0xFF) ^ (mixBlock[i] & 0xFF));
			}
			
			cipher.setPlaintextBlock(block);
			cipher.encrypt();
			mixBlock = cipher.getCiphertextBlock();
			try {
				out.write(mixBlock);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		// add the iv or previous ciphertext
		for(int i = 0; i < 16; i++) {
			block[i] = (byte) ((block[i] & 0xFF) ^ (mixBlock[i] & 0xFF));
		}
		
		cipher.setPlaintextBlock(block);
		cipher.encrypt();
		mixBlock = cipher.getCiphertextBlock();
		try {
			out.write(mixBlock);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		try {
			in.close();
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void startDecryption() {
		byte[] aftermix = new byte[16];
		mixBlock = Arrays.copyOf(iv, iv.length);
		readNextBlock();
		boolean done = false;
		while(!done) {
			cipher.setCiphertextBlock(block);
			cipher.decrypt();
			
			block = cipher.getPlaintextBlock();
			
			// add the iv or previous ciphertext
			for(int i = 0; i < 16; i++) {
				aftermix[i] = (byte) ((block[i] & 0xFF) ^ (mixBlock[i] & 0xFF));
			}
			
			// Check if this block is the padded one
			int validBytes = 16;
			if(!readNextBlock()) {
				validBytes = 16 - (aftermix[15] & 0xFF);
				done = true;
			}
			
			mixBlock = Arrays.copyOf(cipher.getCiphertextBlock(), cipher.getCiphertextBlock().length);
			
			try {
				out.write(aftermix, 0, validBytes);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		try {
			in.close();
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
