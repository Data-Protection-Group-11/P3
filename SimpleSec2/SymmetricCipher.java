import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	
	byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
		(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
		(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/

    public SymmetricCipher() {
        // TODO Auto-generated constructor stub
    }

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/

	/*
	 * The function encryptCBC provides a cyphering using AES, CBC mode with PKCS5 padding
	 * 
	 * @param input a byte array that contains the plain text to be cyphered
	 * @param byteKey a byte array that contains the key to cypher the cipherText
	 * @return the cyphered text with padding in a byte array
	 */

	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		byte[] cipherText = null;	
		int blockSize = 16;
		
		s = new SymmetricEncryption(byteKey);
		
		/*
		 * 1. Calculate the padding needed (incase it is 0, we have to add a padding of the block size)
		 * 2. Create a new array with the size of the input + padding
		 * 3. Calculate the number of blocks needed
		 * 4. Copy the input to the new array paddedText
		 * 5. Add the padding to the new array paddedText
		 * 6. Create a new array cipherText with the size of the number of blocks
		 * 7. Enter into the ciphering for loop
		 * 		7.1. Check if it is the first block, if it is, XOR the IV with that block 
		 * 		7.2. If it is not the first block, XOR the previous block with the current block	
		 * 		7.3. Encrypt the block that we XORed using the encrypt method
		 * 		7.4. Copy the encrypted block into the byte array: previousBlock
		 * 		7.5. Copy the encrypted block into the cipherText array
		 * 8. Return the cipherText array with the fully encrypted text with padding
		 */ 

		
		int padding = blockSize - (input.length % blockSize);
		
		// Create a new array with the size of the input plus the padding

		if(padding == 0) {
			padding = blockSize;
		}
		
		int textLength = input.length + padding;
		byte[] paddedText = new byte[textLength];
		int nBlocks = paddedText.length / blockSize;
		
		System.arraycopy(input, 0, paddedText, 0, input.length);		
		for(int i = 0; i < padding; i++) paddedText[input.length + i] = (byte) padding;

		cipherText = new byte[textLength];
		byte[] previousBlock =  new byte[16];

		/* For loop to encrypt each block */
		for(int i = 0; i < nBlocks; i++) {
			
			byte[] xorBlock = new byte[16];
			for(int j = 0; j < blockSize; j++) {
				if(i == 0) {
					xorBlock[j] = (byte)(paddedText[j] ^ iv[j]);
				}else {
					xorBlock[j] = (byte)(paddedText[j+(i*blockSize)] ^ previousBlock[j]);
				}
			}
			
			previousBlock = s.encryptBlock(xorBlock);
			System.arraycopy(previousBlock, 0, cipherText, (i)*blockSize, blockSize);

		}
		
		return cipherText;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	/*
	 * The function decryptCBC provides a decyphering using AES, CBC mode with PKCS5 padding
	 * 
	 * @param input a byte array that contains the cipherText to be decrypted
	 * @param byteKey a byte array that contains the key to decrypt the cipherText
	 * @return the decrypted text in a byte array
	 */

	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	
		int blockSize = 16;
		int nBlock = input.length / blockSize;
		byte [] finalPlainText = new byte[input.length];
		byte[] currentBlock = new byte[blockSize];
		
		d = new SymmetricEncryption(byteKey);
		
		
		byte[] previousBlock =  new byte[16];
		
		/*
		 * The for loop iterates over the number of blocks
		 * and decrypts each block
		 */

		for(int i = 1; i <= nBlock; i++) {
			System.arraycopy(input, (i-1)*blockSize, currentBlock, 0, blockSize);
			byte[] decryptedBlock =  new byte[16];
			decryptedBlock = d.decryptBlock(currentBlock);
			byte[] xorBlock = new byte[16];
			
			/*
			 * The second for loop iterates over the blockSize
			 * and performs the XOR operation for each byte
			 *
			 * Inside, the if statement checks if the block is the first block
			 * and if it is, it uses the initialization vector
			 * to decrypt the block
			 */

			for(int j = 0; j < blockSize; j++) {
				if(i == 1) {
					xorBlock[j] = (byte)(decryptedBlock[j] ^ iv[j]);
				}else {
					xorBlock[j] = (byte)(decryptedBlock[j] ^ previousBlock[j]);
				}
			}
			
			System.arraycopy(input, (i-1)*blockSize, previousBlock, 0, blockSize);
			
			System.arraycopy(xorBlock, 0, finalPlainText, (i-1)*blockSize, blockSize);
		}
		
		/*
		 * The following code removes the padding, taking the last byte
		 * value, and removing that number of bytes from the plaintext
		 */

		int padding = (int) finalPlainText[finalPlainText.length-1];
		byte[] textNoPadding = new byte[input.length-padding];
		System.arraycopy(finalPlainText, 0, textNoPadding, 0, input.length-padding);		
		
		return textNoPadding;
	}
}


