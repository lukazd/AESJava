import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;


public abstract class ModeOfOperation {
	public static final int BUFFER_SIZE = 2048;
	protected FileInputStream in;
	protected FileOutputStream out;
	protected byte[] readBlock = new byte[BUFFER_SIZE];
	protected byte[] block = new byte[16];
	protected int numBytesRead;
	protected AESCipher cipher;
	
	private int readBlockIndex = 0;
	private int lastBlockIndex = -1;
	private boolean paddedBlock = false;
	
	public ModeOfOperation(String inputFileName, String outputFileName, String key) throws FileNotFoundException {
		try {
			File output = new File(outputFileName);
			output.createNewFile();
			in = new FileInputStream(inputFileName);
			out = new FileOutputStream(output);
			cipher = new AESCipher(key);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean readNextBlock() {
		try {
			if (readBlockIndex > lastBlockIndex) {
				
				numBytesRead = in.read(readBlock, 0, BUFFER_SIZE);
				lastBlockIndex = numBytesRead - 16;
				readBlockIndex = 0;
				
				// Padding for last block
				if (numBytesRead == -1 || numBytesRead < BUFFER_SIZE) {
					// Pad the last block with bytes equal to the number of bytes padded
					numBytesRead = (numBytesRead < 0) ? 0 : numBytesRead;
					lastBlockIndex = numBytesRead - 16;
					int j = 0;
					for (int i = numBytesRead % 16; i < 16; i++) {
						readBlock[numBytesRead + j] = (byte) (16 - numBytesRead%16);
						lastBlockIndex++;
						j++;
					}
					paddedBlock = true;
				}
			}

			block = Arrays.copyOfRange(readBlock, readBlockIndex, readBlockIndex + 16);
			if (readBlockIndex >= lastBlockIndex && paddedBlock) {
				return false;
			}
			readBlockIndex += 16;
			return true;
									
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return true;
	}
	
	public abstract void startEncryption();
	public abstract void startDecryption();
}