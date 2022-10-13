import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SimpleSec {

	//String to hold the name of the private key file.
	public static final String PRIVATE_KEY_FILE = "./data/private.key";

	// String to hold name of the public key file.
	public static final String PUBLIC_KEY_FILE = "./data/public.key";

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
			e.printStackTrace();
		}


		// Encrypt the private key using AES/CBC using the passphrase as key
		
		// Store the encrypted private key in the file "private.key"
	}
	
	public static PublicKey loadPublicKey(String inputFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		// read public key DER file
		File pubKeyFile = new File(inputFile);
        DataInputStream dis = new DataInputStream(new 
        FileInputStream(pubKeyFile));
        byte[] pubKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(pubKeyBytes);
        dis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
		PublicKey pk = keyFactory.generatePublic(pubKeySpec);
		return pk;
	}


	public static PrivateKey loadPrivateKey(String inputFile, byte[] byteKey) throws Exception, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		// read private key from file
		File pubKeyFile = new File(inputFile);
        DataInputStream dis = new DataInputStream(new 
        FileInputStream(pubKeyFile));
        byte[] privKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(privKeyBytes);
        dis.close();
		
		SymmetricCipher s = new SymmetricCipher();
		byte[] dPrivKey = s.decryptCBC(privKeyBytes, byteKey);

 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
			dPrivKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}


	public static void encrypt(String sourceFile, String destinationFile) throws Exception{
		
		// Encrypt sourceFile using AES/CBC and a random AES key (session key)
	

		//generate a random aes key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128); // for example
		Key sessionKey = keyGen.generateKey();

		SymmetricCipher e = new SymmetricCipher();
		byte[] encryptedFile = e.encryptCBC(sourceFile.getBytes(), sessionKey.getEncoded());

		// Session key is encrypted using RSA and the public key
		PublicKey pubKey = loadPublicKey(PUBLIC_KEY_FILE);

		// Encrypt session key using RSALIBRARY.encrypt
		RSALibrary rsa = new RSALibrary();
		byte[] encSessionKey = rsa.encrypt(sessionKey.getEncoded(), pubKey);

		// Concatenate encrypted session key with encrypted sourceFile
		byte[] result = new byte[encSessionKey.length + encryptedFile.length];
		System.arraycopy(encSessionKey, 0, result, 0, encSessionKey.length);
		System.arraycopy(encryptedFile, 0, result, encSessionKey.length, encryptedFile.length);
		
		// As the private key is needed, the user will insert the previous
		// passphrase in order to decrypt the "private.key" file
		Scanner myObj = new Scanner(System.in);  // Create a Scanner object
		System.out.println("Enter passphrase for signing the document");
		String passphrase = myObj.nextLine();	// Read user input
		byte[] byteKey = passphrase.getBytes();

		//get the private key from its file and the passphrase provided:
		PrivateKey privK = loadPrivateKey(PRIVATE_KEY_FILE, byteKey);


		// The resulting concatenation is encrypted with the private key
		byte[] sign = rsa.sign(result, privK);
		
		//concatenate result with signature
		byte[] finalEnc = new byte[result.length + sign.length];
		System.arraycopy(result, 0, finalEnc, 0, result.length);
		System.arraycopy(sign, 0, finalEnc, result.length, sign.length);

		//save in destinationFile
		FileOutputStream out = new FileOutputStream(destinationFile);
		out.write(finalEnc);
		out.close();


		// The encrypted concatenation is again concatenated with the previously
		// encrypted session key

		
	}


	public static void main(String[] args) throws Exception{
		//generate();
		String sourceFile = "./data/data.txt";
		String destinationFile = "./data/dst.enc";
		encrypt(sourceFile, destinationFile);
		System.out.println("Keys created");
		
		/*
		
		switch (var) {
			case "g": 
				generate();
			case "e":
				String sourceFile = "./data/data.txt";
				String destinationFile = "./data/dst.enc";
				System.out.println("!==================================!");
				//String sourceFile = args[1];
				//String destinationFile = args[2];
				//encrypt(sourceFile, destinationFile);
				
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
			*/

	}
}
