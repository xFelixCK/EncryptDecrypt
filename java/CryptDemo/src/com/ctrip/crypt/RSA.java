package com.ctrip.crypt;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import java.security.spec.X509EncodedKeySpec;
import java.security.Signature;

import javax.crypto.Cipher;

public class RSA {

	static byte [] Encrypt(byte []pubKey, byte []text){		
		try{
			X509EncodedKeySpec x509keyspec = new X509EncodedKeySpec(pubKey);
	        
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey key = (RSAPublicKey)kf.generatePublic(x509keyspec);

			Cipher cipher = Cipher.getInstance("RSA"); 
	        cipher.init(Cipher.ENCRYPT_MODE, key); 

	        return cipher.doFinal(text);
		}catch(Exception e){
			return null;
		}
	}
	
	static byte [] Decrypt(byte []priKey, byte []cipherText){
		try{
			PKCS8EncodedKeySpec p8Key = new PKCS8EncodedKeySpec(priKey);
	        
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPrivateKey key = (RSAPrivateKey)kf.generatePrivate(p8Key);

			Cipher cipher = Cipher.getInstance("RSA"); 
	        cipher.init(Cipher.DECRYPT_MODE, key); 

	        return cipher.doFinal(cipherText);
		}catch(Exception e){
			return null;
		}
	}
	
	static byte [] Sign(byte []priKey, byte []text){		
		try{
			PKCS8EncodedKeySpec p8Key = new PKCS8EncodedKeySpec(priKey);
	        
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPrivateKey key = (RSAPrivateKey)kf.generatePrivate(p8Key);

			Signature signet = Signature.getInstance("SHA256withRSA");
			signet.initSign(key);
			signet.update(text);
			byte[] signed = signet.sign(); // 对信息的数字签名

			return signed;
		}catch(Exception e){
			return null;
		}
	}
	
	static boolean VeriySign(byte []pubKey, byte []text, byte []sig){
		try{
			X509EncodedKeySpec x509keyspec = new X509EncodedKeySpec(pubKey);
	        
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKey key = (RSAPublicKey)kf.generatePublic(x509keyspec);
			
			Signature signet = Signature.getInstance("SHA256withRSA");
			signet.initVerify(key);
			signet.update(text);
			return signet.verify(sig); // 对信息的数字签名
			
		}catch(Exception e){
			return false;
		}
	}
}
