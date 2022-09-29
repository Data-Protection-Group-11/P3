package simpleSec;

public class SimpleSec {
	
	public static void main(String[] args) {
		switch (args[0]) {
			case "g": 
				// Generate a pair of RSA keys
				System.out.println("caso g");
				//"Introduce passphrase:"
				
				// Encrypt the private key using AES/CBC using the passphrase as key
				
				// Store the encrypted private key in the file "private.key"
			case "e":
				// Encrypt args[1] using AES/CBC and a random AES key (session key)
				
				// Session key is encrypted using RSA and the public key
				
				// Concatenate encrypted session key with encrypted args[1]
				
				// As the private key is needed, the user will insert the previous
				// passphrase in order to decrypt the "private.key" file
				
				// The resulting concatenation is encrypted with the private key
				
				// The encrypted concatenation is again concatenated with the previously
				// encrypted session key
			case "d":
				// Separate firm and payload

				// Verify firm

				// Separate ciphertext and encrypted session key

				// As private key is needed, introduce passphrase to decrypt the private.key file, and store the private key

				// Decrypt session key using RSA and private key

				// Use the session key to decrypt the ciphertext using AES/CBC

				// Result is stored int he file args[2]
			default:
				System.out.println("Error!");
			}

	}
}
