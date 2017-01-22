package com.polytech;


import java.security.*;
import javax.crypto.*;

public class Entity{

	// Keypairgenerator and keypair

	public KeyPairGenerator keygenerator;
	private KeyPair keypair;
	
	//keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
		
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		// INITIALIZATION
				
		// generate a public/private key
		try{
			
			// get an instance of KeyPairGenerator for RSA	
			// Initialize the key pair generator for 1024 length
			// Generate the key pair
		    keygenerator = KeyPairGenerator.getInstance("RSA");
			keygenerator.initialize(1024);
            keypair = keygenerator.genKeyPair();
            
			// save the public/private key
            thePublicKey = keypair.getPublic();
            thePrivateKey = keypair.getPrivate();
	
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a messageDigest
	  * Parameters
	  * amessageDigest : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] amessageDigest){
		
		try{
			// use of java.security.Signature (Create an object of java.security.Signature for « SHA1withRSA ».)
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature with the private key in SIGN_MODE
            signature.initSign(thePrivateKey);
            
			// update the messageDigest
            signature.update(amessageDigest);
            
			// sign
			return signature.sign();

		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of amessageDigest with aPK
	  * Parameters
	  * amessageDigest : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the messageDigest signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] amessageDigest, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature (Create an object of java.security.Signature for « SHA1withRSA ».)
			Signature signature = Signature.getInstance("SHA1withRSA");

			// Initialize the signature in VERIFY_MODE mode with the public key
            signature.initVerify(aPK);

			// update the messageDigest
            signature.update(amessageDigest);

            // check the signature		
            return signature.verify(aSignature);
            
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a messageDigest (Implementation of our own signature)
	  * Parameters
	  * amessageDigest : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] amessageDigest){
		
		try{
			// get an instance of a cipher with RSA in ENCRYPT_MODE
			// Initialize the signature with the private key          
			  Cipher cipher = Cipher.getInstance("RSA");
		      cipher.init(Cipher.ENCRYPT_MODE, this.thePrivateKey);
		      
			// get an instance of the java.security.messageDigestDigest with sha1
	             MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		
	        // process the digest
	             messageDigest.update(amessageDigest);
	             byte[] digest = messageDigest.digest();
	             
	             byte [] sign = cipher.doFinal(digest);

			// return the encrypted digest
			return sign;
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of amessageDigest with aPK (Implementation of our own check signature)
	  * Parameters
	  * amessageDigest : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the messageDigest signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] amessageDigest, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA in DECRYPT_MODE
			// Init the signature with the public key
		      Cipher cipher = Cipher.getInstance("RSA");
		      cipher.init(Cipher.DECRYPT_MODE, aPK);

			// decrypt the signature
	             byte [] digest1 = cipher.doFinal(aSignature);

			// get an instance of the java.security.messageDigestDigest with sha1
	             MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			
	        // process the digest
	             messageDigest.update(amessageDigest);
	             byte[] digest2 = messageDigest.digest();

			// check if digest1 == digest2 and return the result
			if (digest1 == digest2)
		     return true;
			 else return false;

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt amessageDigest with aPK (RSAEncryption)
	  * Parameters
	  * amessageDigest : byte[] to be encrypted
	  * aPK : a public key used for the messageDigest encryption
	  * Result : byte[] ciphered messageDigest
	  **/
	public byte[] encrypt(byte[] amessageDigest, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
		      Cipher cipher = Cipher.getInstance("RSA");

			// initialize the Cipher in ENCRYPT_MODE and aPK
	             cipher.init(Cipher.ENCRYPT_MODE, aPK);
	       
			// use doFinal to encrypt on the byte[] and return the ciphered byte[]
	             byte [] ciphered = cipher.doFinal(amessageDigest);

			return ciphered;
			
		}
		
		
		catch(Exception e){
		    System.out.println("Encryption error");			
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt amessageDigest with the entity private key (RSADecryption)
	  * Parameters
	  * amessageDigest : byte[] to be encrypted
	  * Result : byte[] deciphered messageDigest
	  **/
	public byte[] decrypt(byte[] amessageDigest){
		try{
			// get an instance of RSA Cipher
		      Cipher cipher = Cipher.getInstance("RSA");


		   // initialize the Cipher in DECRYPT_MODE and aPK
		     cipher.init(Cipher.DECRYPT_MODE, this.thePrivateKey);
	 		

			// use doFinal to decrypt on the byte[] and return the deciphered byte[]
	             byte [] deciphered = cipher.doFinal(amessageDigest);
			
	             
	       return deciphered;
			
		}catch(Exception e){
			System.out.println("Decryption error");
			e.printStackTrace();
			return null;
		}

	}

	public PrivateKey getThePrivateKey() {
		return thePrivateKey;
	}

}