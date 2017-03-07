import java.io.FileNotFoundException;
import java.io.IOException;

public class ECB extends ModeOfOperation {
	
	public ECB(String inputFileName, String outputFileName, String key) throws FileNotFoundException {
		super(inputFileName, outputFileName, key);
	}

	@Override
	public void startEncryption() {
		while(readNextBlock()) {
			cipher.setPlaintextBlock(block);
			cipher.encrypt();
			block = cipher.getCiphertextBlock();
			try {
				out.write(block);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		// write the last block with padding
		cipher.setPlaintextBlock(block);
		cipher.encrypt();
		block = cipher.getCiphertextBlock();
		try {
			out.write(block);
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
		readNextBlock();
		boolean done = false;
		while(!done) {
			cipher.setCiphertextBlock(block);
			cipher.decrypt();
			
			// Check if this block is the padded one
			int validBytes = 16;
			if(!readNextBlock()) {
				validBytes = 16 - (cipher.getPlaintextBlock()[15] & 0xFF);
				done = true;
			}
			
			try {
				out.write(cipher.getPlaintextBlock(), 0, validBytes);
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
