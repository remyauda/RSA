package com.polytech;

/**
 * TD3 - RSA signature, encryption/decryption
 *
 * asymetric clearTextFile SignatureFile CipheredFile DecipheredFile
 **/

import java.security.*;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

public class Asymetric{

	//If we give some arguments, a sequence of encryption and decryption with signature check will be done to test our implementation of RSA signature and RSA Ciphering.
	/*The first argument must be the path of the clearText ie res/clearText.txt for this project.
	 *The second argument must be the path of the file which will contain the signature done by sign and MySign (ie signature/signature.txt)
	 *The third argument must be the path of the file which will contain the encrypt message (ie myEncryptedMessages/encrypted_messages.txt)
	 *The fourth argument must be the path of the file which will contain the decrypt message (ie myDecryptedMessages/decrypted_messages.txt)*/
	//Whether or not we give some arguments, the Secure session key exchange will be done (RSA Signature Implementation => 3. Secure session key exchange) 
	static public void main(String argv[]){

		// INITIALIZATION

		// load the bouncycastle provider
		//Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		//Security.addProvider(prov);

		// create two new entity
		Entity Alice = new Entity();
		Entity Bob = new Entity();
		
		/******TEST OF OUR IMPLEMENTATION OF RSA SIGNATURE AND RSA CIPHERING******/

		if(argv.length>0){ //if there is some arguments, we test our implementation of RSA signature and RSA Ciphering.
			System.out.println("TEST OF OUR IMPLEMENTATION OF RSA SIGNATURE AND RSA CIPHERING: ");
			try{

				// GET THE CLEAR TEXT
				File aFile = new File(argv[0]);//create an object file with the file present in the path location (here the location of the clear file).
				FileInputStream in = new FileInputStream(aFile);//opening a connection to the clear file
				byte[] aMessage = new byte[(int)aFile.length()];
				in.read(aMessage);
				in.close();

				// RSA SIGNATURE
				System.out.println("\nRSA SIGNATURE\n");
				// MAKE ALICE SIGN IT
				// display the clear text
				System.out.println("Message == \n"+new String(aMessage));
				// sign it
				byte[] aSignature = Alice.sign(aMessage);
				// display and store the signature
				System.out.println("");
				System.out.println("Alice Signature == \n"+new String(aSignature));
				System.out.println("");
				FileOutputStream out = new FileOutputStream(new File(argv[1]));
				out.write(aSignature);
				out.close();

				// BOB CHECKS THE ALICE SIGNATURE
				System.out.println("Bob signature verification == \n"+Bob.checkSignature(aMessage, aSignature, Alice.thePublicKey));

				// MY RSA SIGNATURE
				System.out.println("\nMY RSA SIGNATURE\n");
				// MAKE ALICE SIGN IT
				// display the clear text
				System.out.println("Message == \n"+new String(aMessage));
				// sign it
				aSignature = Alice.mySign(aMessage);
				// display and store the signature
				System.out.println("");
				System.out.println("Alice Signature == \n"+new String(aSignature));
				System.out.println("");
				out = new FileOutputStream(new File(argv[1]));
				out.write(aSignature);
				out.close();

				// BOB CHECKS THE ALICE SIGNATURE
				System.out.println("Bob signature verification == \n"+Bob.myCheckSignature(aMessage, aSignature, Alice.thePublicKey));

				// RSA ENCRYPTION/DECRYPTION
				System.out.println("\nRSA ENCRYPTION\n");
				// bob encrypt a message with the alice public key
				System.out.println("Clear Text == \n"+new String(aMessage));
				byte[] aCiphered = Bob.encrypt(aMessage, Alice.thePublicKey);
				System.out.println("");
				System.out.println("Ciphered Text== \n"+new String(aCiphered)+"\n");
				out = new FileOutputStream(new File(argv[2]));
				out.write(aCiphered);
				out.close();

				// alice decrypt the message
				byte[] aDeciphered = Alice.decrypt(aCiphered);
				System.out.println("");
				System.out.println("Deciphered Text== \n"+new String(aDeciphered));
				System.out.println("");
				out = new FileOutputStream(new File(argv[3]));
				out.write(aDeciphered);
				out.close();
			}catch(Exception e){
				e.printStackTrace();
				System.out.println("java Asymetric clearTextFile SignatureFile CipheredFile DecipheredFile");
			}

		}
		
		System.out.println("");
		System.out.println("**************************************************************");
		System.out.println("");

		//Whether or not we have given some arguments, we test our protocol between Alice and Bob for a secure session key exchange
		
		/******BEGIN OF THE PROTOCOL BETWEEN ALICE AND BOB FOR A SECURE SESSION KEY EXCHANGE******/
		
		System.out.println("TEST OF THE PROTOCOL BETWEEN ALICE AND BOB FOR A SECURE SESSION KEY EXCHANGE: ");
		System.out.println("");
		final String PUBLIC_KEY_DIRECTORY = "Public_key/";
		final String SESSION_KEY_DIRECTORY = "Session_key/";
		final String ENCRYPTED_MESSAGES_DIRECTORY = "encrypted_messages/";
		final String DECRYPTED_MESSAGES_DIRECTORY = "decrypted_messages/";

		//Clear all the directories
		deleteDirectory(PUBLIC_KEY_DIRECTORY); //delete all the files present in the Public_key directory
		deleteDirectory(SESSION_KEY_DIRECTORY); //delete all the files present in the Session_key directory
		deleteDirectory(ENCRYPTED_MESSAGES_DIRECTORY); //delete all the files present in the encrypted_messages directory
		deleteDirectory(DECRYPTED_MESSAGES_DIRECTORY); //delete all the files present in the decrypted_messages directory


		final String PUBLIC_KEY_FILE_PATH = "Public_key/publicKey.txt";//define the path where the public key will be store and exchange.

		PublicKey AlicePublicKey = Alice.thePublicKey ; //get the public key of Alice
		PublicKey BobPublicKeyFromAlice = null; 

		ObjectOutputStream oos_publicKey = null; // to send public key
		ObjectInputStream iis_publicKey = null; // to read public key

		/***1. Alice sends her public key to Bob.***/

		//write the public key of Alice in a file that Bob (and anybody) could read. Therefore, Alice sends her public key to Bob.
		try {
			oos_publicKey = new ObjectOutputStream( //define the stream for write the public key
					new BufferedOutputStream( //to go faster
							new FileOutputStream( //write in a file
									new File(PUBLIC_KEY_FILE_PATH)))); //precise the path of the file that we want to write in.

			//Write (Serialize) the Alice's public key in the file
			oos_publicKey.writeObject(AlicePublicKey);

			//Close the stream 
			oos_publicKey.close();


			//Bob now retrieve the public key from Alice:	

			iis_publicKey = new ObjectInputStream( //define the stream for read the public key
					new BufferedInputStream(//to go faster
							new FileInputStream(//read in a file
									new File(PUBLIC_KEY_FILE_PATH))));//precise the path of the file that we want to read in.

			//Bob now retrieve the public key from Alice
			try {
				BobPublicKeyFromAlice = (PublicKey) iis_publicKey.readObject();//read the Alice’s public key written in the file.
				Bob.thePublicKey = BobPublicKeyFromAlice; //Bob get the public key which has been send by Alice.
			} catch (ClassNotFoundException e) {
				System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
				e.printStackTrace();
			}
			//Close the stream 
			iis_publicKey.close();

		} catch (FileNotFoundException e) {
			System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
			e.printStackTrace();
		}     
		
		System.out.println("1. Alice sends her public key to Bob: Succes");

		/***2. Bob generate a DES session key.***/

		// Bob generate a DES session key: session key creation
		KeyGenerator keygen = null;
		SecretKey sessionKey = null;
		try {
			keygen = KeyGenerator.getInstance("DES"); //Initialize the generator to DES (better to use AES)
			sessionKey = keygen.generateKey(); //Generate the DES session key
		} catch (NoSuchAlgorithmException e1) {
			System.out.println("Cause: "+e1.getCause()+" Mesage: "+e1.getMessage());
			e1.printStackTrace();
		}
		
		System.out.println("2. Bob generate a DES session key: Succes");

		/***3. Bob encrypts it with Alice’s public key.***/

		//Bob encrypts the session key with Alice’s public key: encryption of session key by Bob
		SealedObject sessionKeyObj = null;
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //Initialize the cipher to RSA encryption
			cipher.init(Cipher.ENCRYPT_MODE, BobPublicKeyFromAlice); //Initialize the cipher to encryption mode with the Alice’s public key.
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
			e.printStackTrace();
		}
		try {
			sessionKeyObj = new SealedObject(sessionKey.getEncoded(), cipher); //RSA encryption of the sessionKey with the Alice’s public key and encapsulates it in serialized format (The serialize format is the SealedObject).
		} catch (IllegalBlockSizeException | IOException e) {
			System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
			e.printStackTrace();
		}

		//Bob send the encrypted session key to Alice
		final String PUBLIC_SESSION_KEY_FILE_PATH = "Session_key/sessionKey.txt";//define the path where the session key will be store and exchange.
		ObjectOutputStream oos_sessionKey; // to send the session key
		try {
			oos_sessionKey = new ObjectOutputStream( //write object
					new BufferedOutputStream( //to go faster
							new FileOutputStream( //write in a file
									new File(PUBLIC_SESSION_KEY_FILE_PATH)))); //precise the path of the file that we want to write in.

			oos_sessionKey.writeObject(sessionKeyObj);//serialize the encrypted session key
			oos_sessionKey.close();
		} catch (IOException e2) {
			System.out.println("Cause: "+e2.getCause()+" Mesage: "+e2.getMessage());
			System.out.println("Error sending session key to Alice");
		}
		
		System.out.println("3. Bob encrypts it with Alice’s public key: Succes");

		/***4. Alice decrypts the DES key with her private key.***/

		//Alice retrieve the encrypted session key from Bob and then decrypt it with her private key

		//Alice retrieve the session key from Bob
		ObjectInputStream iis_sessionKey = null; // to read public key
		try {
			iis_sessionKey = new ObjectInputStream( //define the stream for read the session key
					new BufferedInputStream(//to go faster
							new FileInputStream(//read in a file
									new File(PUBLIC_SESSION_KEY_FILE_PATH))));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}//precise the path of the file that we want to read in.

		//Alice now retrieve the session key from Bob
		SealedObject AliceSesssionKeyFromBob = null;
		try {
			try {
				AliceSesssionKeyFromBob = (SealedObject) iis_sessionKey.readObject();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}//read the Bob's session key written in the file.
		} catch (ClassNotFoundException e) {
			System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
			e.printStackTrace();
		}
		//Close the stream 
		try {
			iis_sessionKey.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		//Alice has retrieved the encrypted session key. She must now decrypt it.
		SecretKey sessionKey_reconstruct = null;
		try {       
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //Initialize the cipher with RSA algorithm
			cipher1.init(Cipher.DECRYPT_MODE, Alice.getThePrivateKey()); //Initialize the cipher in decript mode with her private key

			// Decrypt the session key and receive an DES key in a byte encoded form from Bob
			byte[] encoded_decryptSessionKey = (byte[])AliceSesssionKeyFromBob.getObject(cipher1);/*The encapsulated session key is unsealed (ie decrypt) using the given Cipher and de-serialized, before it is returned.*/
			// reconstruct DES key from byte encoded form
			sessionKey_reconstruct = new SecretKeySpec(encoded_decryptSessionKey, 0, encoded_decryptSessionKey.length, "DES"); // reconstruct DES key from byte encoded form
		} catch (GeneralSecurityException gse) {
			System.out.println("Error: wrong cipher to decrypt session key");
		} catch (IOException ioe) {
			System.out.println("Error receiving session key");
		} catch (ClassNotFoundException ioe) {
			System.out.println("Error: cannot typecast to byte array");
		}
		
		System.out.println("4. Alice decrypts the DES key with her private key: Succes");

		/***5. Alice sends a message to Bob with her session key***/

		final String CLEARTEXT_FILE_PATH = "res/clearText.txt";//define the path where the clear text is stored.
		final String ENCRYPTED_MESSAGES_FILE_PATH = "encrypted_messages/encrypted_messages";//define the path where the encrypted messages will be stored.
		final String DECRYPTED_MESSAGES_FILE_PATH = "decrypted_messages/decrypted_messages.txt";//define the path where the decrypted messages will be stored.
		final String SUFFIX = ".txt";
		int compteur =1;

		try {

			Scanner fromFile = new Scanner(new File(CLEARTEXT_FILE_PATH)); //define a new scanner to read the clearText file.

			//read the clearText file
			while (fromFile.hasNextLine()) {
				String message = fromFile.nextLine();//read each lines
				SealedObject encryptedMsg = null;
				try {
					Cipher cipher1 = Cipher.getInstance("DES"); //Set the cipher to DES
					cipher1.init(Cipher.ENCRYPT_MODE, sessionKey_reconstruct); //Initialize the cipher to encryption mode with the reconstructed session key
					encryptedMsg = new SealedObject(message, cipher1); //encrypted each message with the reconstructed session key
				} catch (GeneralSecurityException gse) {
					System.out.println("Error: wrong cipher to encrypt message");
				} catch (IOException ioe) {
					System.out.println("Error creating SealedObject");
				}

				ObjectOutputStream oos_messages; // to send encrypted messages
				//write the encrypted message 
				try {
					oos_messages = new ObjectOutputStream( //define the stream for write the encrypted messages
							new BufferedOutputStream( //to go faster
									new FileOutputStream( //write in a file
											new File(ENCRYPTED_MESSAGES_FILE_PATH + compteur + SUFFIX)))); //precise the path of the file that we want to write in.

					//Write the encrypted messages
					oos_messages.writeObject(encryptedMsg);

					//Close the stream 
					oos_messages.close();
				}
				catch(FileNotFoundException e) {
					System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
					e.printStackTrace();
				} catch (IOException e) {
					System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
					e.printStackTrace();
				}    

				compteur++;

			}

			fromFile.close();  // close input file stream
			//System.out.println("All messages are sent to Bob");

		} catch (FileNotFoundException fnfe) {
			System.out.println("Error: " + ENCRYPTED_MESSAGES_FILE_PATH + compteur + SUFFIX + " doesn't exist");
		} 
		
		System.out.println("5. Alice sends a message to Bob with her session key: Succes");

		/***6. Bob decrypts the message with the session key.***/

		File monRepertoire=new File(ENCRYPTED_MESSAGES_DIRECTORY);
		//count the number of file containing the encrypted message
		File[] f = monRepertoire.listFiles();
		int nbEncryptFiles = 0;
		for (int i = 0 ; i < f.length ; i++) {
			if (f[i].isFile()) {
				nbEncryptFiles++;
			}
		}//nbEncryptFiles is the number of files in the directory encrypted_messages

		ObjectInputStream iis_encryptedMessage;
		SealedObject encryptedMessage;

		clearFile(DECRYPTED_MESSAGES_FILE_PATH); //clear the DECRYPTED_MESSAGES_FILE_PATH before write in it.
		for(int i = 1; i <= nbEncryptFiles; i++){
			String plainText = null;
			try{		
				iis_encryptedMessage = new ObjectInputStream( //define the stream for read the public key
						new BufferedInputStream(//to go faster
								new FileInputStream(//read in a file
										new File(ENCRYPTED_MESSAGES_FILE_PATH + i + SUFFIX))));//precise the path of the file that we want to read in.

				//Bob now retrieve the public key from Alice

				try {
					encryptedMessage = (SealedObject) iis_encryptedMessage.readObject();//read the Alice’s public key written in the file.			
					Cipher cipher1 = null;
					// Alice and Bob use the same AES key/transformation
					try {
						cipher1 = Cipher.getInstance("DES");
						cipher1.init(Cipher.DECRYPT_MODE, sessionKey);
					} catch (NoSuchAlgorithmException | NoSuchPaddingException
							| InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					try {
						plainText = (String) encryptedMessage.getObject(cipher1);
					} catch (ClassNotFoundException | IllegalBlockSizeException
							| BadPaddingException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} catch (ClassNotFoundException e) {
					System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
					e.printStackTrace();
				}
				//Close the stream 
				iis_encryptedMessage.close();

			} catch (FileNotFoundException e) {
				System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
				e.printStackTrace();
			} catch (IOException e) {
				System.out.println("Cause: "+e.getCause()+" Mesage: "+e.getMessage());
				e.printStackTrace();
			} 

			writeAndAppendFile(DECRYPTED_MESSAGES_FILE_PATH, plainText); //write in the file

		}

		System.out.println("6. Bob decrypts the message with the session key: Succes");
		System.out.println("");
		System.out.println("The secure session key exchange has been completed successfully !");
		System.out.println("");
		System.out.println("You can see the encrypted messages in the directory: encrypted_messages and the decrypted messages in the directory: decrypted_messages");

	}

	//append a file with a specified text in a specified by the destination 
	static void writeAndAppendFile(String destination, String text) { 
		try(FileWriter fw = new FileWriter(destination, true);
				BufferedWriter bw = new BufferedWriter(fw);
				PrintWriter out = new PrintWriter(bw))
		{

			out.println(text);
			//more code
			//out.println("more text");
			//more code

		} catch (IOException e) {
			//exception handling left as an exercise for the reader
		}
	}  

	//clear a file at a specified destination
	static void clearFile(String destination) { 
		try(FileWriter fw = new FileWriter(destination, false);
				BufferedWriter bw = new BufferedWriter(fw);
				PrintWriter out = new PrintWriter(bw))
		{		

		} catch (IOException e) {
			//exception handling left as an exercise for the reader
		}
	}  

	//Delete all the files within a specified directory
	static void deleteDirectory( String emplacement )
	{
		File path = new File( emplacement ); //create a new file
		if( path.exists() ) 
		{
			File[] files = path.listFiles(); //get the list of the files
			for( int i = 0 ; i < files.length ; i++ )
			{
				//if it is a directory, we delete it
				if( files[ i ].isDirectory() ) 
				{
					deleteDirectory( path+"\\"+files[ i ] ); 
				}
				files[ i ].delete();
			}
		}
	}

}