package com.ctrip.crypt;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import sun.misc.BASE64Encoder;

public class TestCrypt {
	public static void main(String []args){

		TestAes256();
		TestSHA256();
		TestRSA();
		TestPBKDF2();
	}
	
	public static void TestAes256(){
		System.out.println("Test aes 256");
		String key = "111112222333344445555666677778888";
		String plain = "Test aes 256, 00112233445566778899";
		String cipher = AES256.Encrypt(key, plain);
		System.out.println("明文: " + plain);
		System.out.println("加密后: " + cipher);
		String plain1 = AES256.Decrypt(key, cipher);
		System.out.println("解密后: " + plain1);
	}
	
	public static void TestSHA256(){
		System.out.println("\nTest sha 256");
		String text = "Test sha 256 abcdefghijklmnopqrstuvwxyz";
		String digest = SHA256.Digest(text);
		System.out.println("明文: " + text);
		System.out.println("摘要值: " + digest);
	}
	
	public static void TestRSA(){
		System.out.println("\nTest rsa 2048");
		byte []pubKey;
		byte []priKey;
		String text =  "Test RSA, 1234abcd";
		try{
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
	        //密钥位数  
	        keyPairGen.initialize(2048);
	        //密钥对  
	        KeyPair keyPair = keyPairGen.generateKeyPair();
			pubKey = keyPair.getPublic().getEncoded();	//X509格式
			priKey = keyPair.getPrivate().getEncoded();	//pkcs#8格式
		}catch(Exception e){
			return;
		}
		System.out.println("明文: " + text);
		byte []cip = RSA.Encrypt(pubKey, text.getBytes());
		String str = new BASE64Encoder().encode(cip);
		System.out.println("加密后:	" + str);
		byte []plain = RSA.Decrypt(priKey, cip);
		System.out.println("解密后:	" + new String(plain));
		
		System.out.println("\nTest Sign");
		byte []sig = RSA.Sign(priKey, text.getBytes());
		str = new BASE64Encoder().encode(sig);
		System.out.println("Signature: " + str);
		boolean bVerify = RSA.VeriySign(pubKey, text.getBytes(), sig);
		System.out.println("VeritySign: " + bVerify);
	}
	
	public static void TestPBKDF2(){
			System.out.println("\nTest pbkdf2");
			
			String psw = "password01!";
			
			int i;
			byte []dk = null;
			long beg = System.currentTimeMillis();
			for (i=0; i<1000; i++){
				dk = PBKDF2.DeriveKey(psw);
			}
			long end = System.currentTimeMillis();
			System.out.println("pbkdf2, 1000 times : " + (end-beg));
			
			System.out.println("密码:	" + psw);
			String strdk = new BASE64Encoder().encode(dk);
			System.out.println("pbkdf2后:	" + strdk);
			
			System.out.println("Verify:		" + PBKDF2.Verify(psw, dk));
			
	}
}
