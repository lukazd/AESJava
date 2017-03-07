import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;


public class AESCipher {
	private byte[] key = new byte[16];
	private byte[] plaintextBlock;
	private byte[] ciphertextBlock;
	private byte[] intermediateBlock;
	private byte[][] roundKeys = new byte[11][16];
	byte [][] multiplicationTable = new byte[256][9];
	
	private final int ROUNDS = 10;
	private final int NUM_BYTES = 16;
	
	private final short[] roundCoefficients = new short[] {
		0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	};
	
	private final short[][] sBox = new short[][] { 
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
	};
	
	private final short[][] invSBox = new short[][] { 
		{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
	};
	
	public AESCipher(String key) {
		this.key = DatatypeConverter.parseHexBinary(key);
		generateRoundKeys();
		generateMultiplicationTable();
	}

	public String getKey() {
		return DatatypeConverter.printHexBinary(key);
	}

	public void setKey(String key) {
		
		this.key = DatatypeConverter.parseHexBinary(key);
		generateRoundKeys();
	}
	
	public byte[] getPlaintextBlock() {
		return plaintextBlock;
	}

	public void setPlaintextBlock(byte[] plaintextBlock) {
		this.plaintextBlock = plaintextBlock;
	}
	
	public byte[] getCiphertextBlock() {
		return ciphertextBlock;
	}

	public void setCiphertextBlock(byte[] ciphertextBlock) {
		this.ciphertextBlock = ciphertextBlock;
	}
	
	public void encrypt() {
		intermediateBlock = plaintextBlock.clone();
		keyAddition(0);
		for (int i = 1; i <= ROUNDS; i++) {
			byteSubstitution();
			shiftRows();
			
			// DON'T mix column for last round
			if (i != ROUNDS) {
				mixColumn();
			}
			
			keyAddition(i);
		}
		ciphertextBlock = intermediateBlock.clone();
	}
	
	public void decrypt() {
		intermediateBlock = ciphertextBlock.clone();
		
		for (int i = ROUNDS; i >= 1; i--) {
			keyAddition(i);
			// DON'T mix column for first round
			if (i != ROUNDS) {
				invMixColumn();
			}
			invShiftRows();
			invByteSubstitution();
		}
		keyAddition(0);
		plaintextBlock = intermediateBlock.clone();		
	}
	
	private void generateRoundKeys() {
		roundKeys[0] = key;
		for (int i = 1; i < roundKeys.length; i++) {
			// g function
			
			// rotate bytes
			byte[] gOutput = new byte[4];
			gOutput[0] = roundKeys[i-1][13];
			gOutput[1] = roundKeys[i-1][14];
			gOutput[2] = roundKeys[i-1][15];
			gOutput[3] = roundKeys[i-1][12];
			
			// substitute
			for (int j = 0; j < 4; j++) {
				gOutput[j] = (byte) sBox[(gOutput[j] & 0xF0) >> 4][gOutput[j] & 0x0F];
			}
			
			// add round coefficient
			gOutput[0] = (byte) (gOutput[0] ^ roundCoefficients[i]);
			
			// end g function
			
			// calculate the first word
			for (int j = 0; j < 4; j++) {
				roundKeys[i][j] = (byte) (gOutput[j] ^ roundKeys[i-1][j]);
			}
			
			// calculate the remaining words
			for (int j = 4; j < 16; j++) {
				roundKeys[i][j] = (byte) (roundKeys[i][j - 4] ^ roundKeys[i-1][j]);
			}
		}
	}
	
	private void keyAddition(int round) {
		for (int i = 0; i < intermediateBlock.length; i++) {
			intermediateBlock[i] = (byte) (intermediateBlock[i] ^ roundKeys[round][i]);
		}
	}
	
	private void byteSubstitution() {
		// substitute
		for (int i = 0; i < NUM_BYTES; i++) {
			intermediateBlock[i] = (byte) sBox[(intermediateBlock[i] & 0xF0) >> 4][intermediateBlock[i] & 0x0F];
		}
	}
	
	private void invByteSubstitution() {
		// substitute
		for (int i = 0; i < NUM_BYTES; i++) {
			intermediateBlock[i] = (byte) invSBox[(intermediateBlock[i] & 0xF0) >> 4][intermediateBlock[i] & 0x0F];
		}
	}
	
	private void shiftRows() {
		byte temp = intermediateBlock[1];
		intermediateBlock[1] = intermediateBlock[5];
		intermediateBlock[5] = intermediateBlock[9];
		intermediateBlock[9] = intermediateBlock[13];
		intermediateBlock[13] = temp;
		
		temp = intermediateBlock[2];
		intermediateBlock[2] = intermediateBlock[10];
		intermediateBlock[10] = temp;
		
		temp = intermediateBlock[3];
		intermediateBlock[3] = intermediateBlock[15];
		intermediateBlock[15] = intermediateBlock[11];
		intermediateBlock[11] = intermediateBlock[7];
		intermediateBlock[7] = temp;
		
		temp = intermediateBlock[6];
		intermediateBlock[6] = intermediateBlock[14];
		intermediateBlock[14] = temp;
	}
	
	private void invShiftRows() {
		byte temp = intermediateBlock[1];
		intermediateBlock[1] = intermediateBlock[13];
		intermediateBlock[13] = intermediateBlock[9];
		intermediateBlock[9] = intermediateBlock[5];
		intermediateBlock[5] = temp;
			
		temp = intermediateBlock[2];
		intermediateBlock[2] = intermediateBlock[10];
		intermediateBlock[10] = temp;
		
		temp = intermediateBlock[3];
		intermediateBlock[3] = intermediateBlock[7];
		intermediateBlock[7] = intermediateBlock[11];
		intermediateBlock[11] = intermediateBlock[15];
		intermediateBlock[15] = temp;
		
		temp = intermediateBlock[6];
		intermediateBlock[6] = intermediateBlock[14];
		intermediateBlock[14] = temp;
	}
	
	private void mixColumn() {
		byte [] c = Arrays.copyOf(intermediateBlock, intermediateBlock.length);
		
		// Look up the matrix multiplications
		for (int i = 0; i < 16; i += 4) {
			intermediateBlock[i]     = (byte) (multiplicationTable[c[i] & 0xFF][1] ^ multiplicationTable[c[i + 1] & 0xFF][2] ^ multiplicationTable[c[i + 2] & 0xFF][0] ^ multiplicationTable[c[i + 3] & 0xFF][0]);
			intermediateBlock[i + 1] = (byte) (multiplicationTable[c[i] & 0xFF][0] ^ multiplicationTable[c[i + 1] & 0xFF][1] ^ multiplicationTable[c[i + 2] & 0xFF][2] ^ multiplicationTable[c[i + 3] & 0xFF][0]);
			intermediateBlock[i + 2] = (byte) (multiplicationTable[c[i] & 0xFF][0] ^ multiplicationTable[c[i + 1] & 0xFF][0] ^ multiplicationTable[c[i + 2] & 0xFF][1] ^ multiplicationTable[c[i + 3] & 0xFF][2]);
			intermediateBlock[i + 3] = (byte) (multiplicationTable[c[i] & 0xFF][2] ^ multiplicationTable[c[i + 1] & 0xFF][0] ^ multiplicationTable[c[i + 2] & 0xFF][0] ^ multiplicationTable[c[i + 3] & 0xFF][1]);
		}
	}
	
	private void invMixColumn() {
		byte [] c = Arrays.copyOf(intermediateBlock, intermediateBlock.length);
		
		// Look up the matrix multiplications
		for (int i = 0; i < 16; i += 4) {
			intermediateBlock[i]     = (byte) (multiplicationTable[c[i] & 0xFF][8] ^ multiplicationTable[c[i + 1] & 0xFF][6] ^ multiplicationTable[c[i + 2] & 0xFF][7] ^ multiplicationTable[c[i + 3] & 0xFF][5]);
			intermediateBlock[i + 1] = (byte) (multiplicationTable[c[i] & 0xFF][5] ^ multiplicationTable[c[i + 1] & 0xFF][8] ^ multiplicationTable[c[i + 2] & 0xFF][6] ^ multiplicationTable[c[i + 3] & 0xFF][7]);
			intermediateBlock[i + 2] = (byte) (multiplicationTable[c[i] & 0xFF][7] ^ multiplicationTable[c[i + 1] & 0xFF][5] ^ multiplicationTable[c[i + 2] & 0xFF][8] ^ multiplicationTable[c[i + 3] & 0xFF][6]);
			intermediateBlock[i + 3] = (byte) (multiplicationTable[c[i] & 0xFF][6] ^ multiplicationTable[c[i + 1] & 0xFF][7] ^ multiplicationTable[c[i + 2] & 0xFF][5] ^ multiplicationTable[c[i + 3] & 0xFF][8]);
		}
	}
	
	private void generateMultiplicationTable() {
		// generate the multiplication table for each byte
		
		for (int i = 0; i < 256; i++) {
			
			// multiply by 1
			multiplicationTable[i][0] = (byte) i;
			
			// multiply by 2
			multiplicationTable[i][1] = (byte) (i << 1);
			if ((i & 0x80) != 0) {
				multiplicationTable[i][1] = (byte) (multiplicationTable[i][1] ^ 0x1B);
			}
			
			// multiply by 4
			multiplicationTable[i][3] = (byte) (i << 2);
			if ((i & 0x80) != 0) {
				multiplicationTable[i][3] = (byte) (multiplicationTable[i][3] ^ 0x36);
			}
			if ((i & 0x40) != 0) {
				multiplicationTable[i][3] = (byte) (multiplicationTable[i][3] ^ 0x1B);
			}
			
			// multiply by 8
			multiplicationTable[i][4] = (byte) (i << 3);
			if ((i & 0x80) != 0) {
				multiplicationTable[i][4] = (byte) (multiplicationTable[i][4] ^ 0x6C);
			}
			if ((i & 0x40) != 0) {
				multiplicationTable[i][4] = (byte) (multiplicationTable[i][4] ^ 0x36);
			}
			if ((i & 0x20) != 0) {
				multiplicationTable[i][4] = (byte) (multiplicationTable[i][4] ^ 0x1B);
			}
			
			// multiply by 3
			multiplicationTable[i][2] = (byte) (multiplicationTable[i][0]^multiplicationTable[i][1]);

			// multiply by 9
			multiplicationTable[i][5] = (byte) (multiplicationTable[i][4]^multiplicationTable[i][0]);
			
			// multiply by B
			multiplicationTable[i][6] = (byte) (multiplicationTable[i][4]^multiplicationTable[i][1]^multiplicationTable[i][0]);
			
			// multiply by D
			multiplicationTable[i][7] = (byte) (multiplicationTable[i][4]^multiplicationTable[i][3]^multiplicationTable[i][0]);
			
			// multiply by E
			multiplicationTable[i][8] = (byte) (multiplicationTable[i][4]^multiplicationTable[i][3]^multiplicationTable[i][1]);
		}
	}
}
