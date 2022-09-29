import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.Scanner;

public class SimpleSec {

	//String to hold the name of the private key file.
	public static final String PRIVATE_KEY_FILE = "./private.key";

	// String to hold name of the public key file.
	public static final String PUBLIC_KEY_FILE = "./public.key";

	public static void generate(){
		// Generate a pair of RSA keys
		System.out.println("caso g");
		//"Introduce passphrase:"
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter password for encrypting private key");

		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();  

		//Create public and private key using RSALibrary
		RSALibrary rsa = new RSALibrary();
		Key pv = null;
		KeyPair kp = null;

		try{
			kp = rsa.generateKeys();
			pv = kp.getPrivate();
			
		} catch (Exception e){
			e.getStackTrace();
		}

		SymmetricCipher s = new SymmetricCipher();
		try {
			byte[] ePrivKey = s.encryptCBC(pv.getEncoded(), byteKey);
			
			 // Store the public key in the file PUBLIC_KEY_FILE	  
			OutputStream out = new FileOutputStream(PUBLIC_KEY_FILE);
			out.write(kp.getPublic().getEncoded());
			out.close();

			//Store the private key in the file PRIVATE_KEY_FILE
			out = new FileOutputStream(PRIVATE_KEY_FILE);
			out.write(ePrivKey);
			out.close();

		} catch (Exception e){

		}


		// Encrypt the private key using AES/CBC using the passphrase as key
		
		// Store the encrypted private key in the file "private.key"
	}
	
	public static void main(String[] args) {
		switch ("g") {
			case "g": 
				generate();
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
