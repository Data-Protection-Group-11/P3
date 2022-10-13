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
	public SymmetricCipher(){
		System.out.println("Buenatarde");
	}

	public SymmetricCipher(byte [] byteKey) {
		
		Path path = Paths.get("./test.txt");
		String input = new String();
		try {
			input = Files.readString(path);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] inputBytes = input.getBytes();
		
		try {
			byte[] result = encryptCBC(inputBytes, byteKey);
			System.out.println(new String(result));
			
			OutputStream out = new FileOutputStream("./test0.enc");
			out.write(result);
			out.close();
			
			byte[] text = decryptCBC(result, byteKey);
			System.out.println(new String(text, "UTF-8"));
			
			out = new FileOutputStream("./test0.dec");
			out.write(text);
			out.close();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		
		byte[] ciphertext = null;	
		int blocksize = 16;
		
		s = new SymmetricEncryption(byteKey);
		
		int padding = blocksize - (input.length % blocksize);
		
		if(padding == 0) {
			padding = blocksize;
		}
		
		int text_length = input.length + padding;
		byte[] padded_text = new byte[text_length];
		
		for ( int i = 0; i < input.length; i++) padded_text[i] = input[i];
		
		ciphertext = new byte[text_length];
		
		for(int i = 0; i < padding; i++) padded_text[input.length + i] = (byte)padding;

		int n_blocks = padded_text.length / blocksize;
		
			// Generate the plaintext with padding
		byte[] previous_block =  new byte[16];
		for(int i = 0; i < n_blocks; i++) {
			
			byte[] xor_block = new byte[16];
			for(int j = 0; j < blocksize; j++) {
				if(i == 0) {
					xor_block[j] = (byte)(padded_text[j] ^ iv[j]);
				}else {
					xor_block[j] = (byte)(padded_text[j+(i*blocksize)] ^ previous_block[j]);
				}
			}
			
			previous_block = s.encryptBlock(xor_block);
			
			System.arraycopy(previous_block, 0, ciphertext, (i)*blocksize, blocksize);

		}
			// Generate the ciphertext
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
	
		int blocksize = 16;
		int n_block = input.length / blocksize;
		byte [] finalplaintext = new byte[input.length];
		byte[] current_block = new byte[blocksize];
		
		d = new SymmetricEncryption(byteKey);
		
		
		byte[] previous_block =  new byte[16];
		
		for(int i = 1; i <= n_block; i++) {
			System.arraycopy(input, (i-1)*blocksize, current_block, 0, blocksize);
			byte[] decrypted_block =  new byte[16];
			decrypted_block = d.decryptBlock(current_block);
			byte[] xor_block = new byte[16];
			
			for(int j = 0; j < blocksize; j++) {
				if(i == 1) {
					xor_block[j] = (byte)(decrypted_block[j] ^ iv[j]);
				}else {
					xor_block[j] = (byte)(decrypted_block[j] ^ previous_block[j]);
				}
			}
			
			System.arraycopy(input, (i-1)*blocksize, previous_block, 0, blocksize);
			
			System.arraycopy(xor_block, 0, finalplaintext, (i-1)*blocksize, blocksize);
		}
		
		// Generate the plaintext
		int padding = (int) finalplaintext[finalplaintext.length-1];
		
		byte[] text_no_padding = new byte[input.length-padding];
		System.arraycopy(finalplaintext, 0, text_no_padding, 0, input.length-padding);
		// Eliminate the padding
		
			
		
		return text_no_padding;
	}
}


