package com.ctrip.crypt;

import java.security.MessageDigest;

import sun.misc.BASE64Encoder;

public class SHA256 {
	static byte[] Digest(byte []text){
		 try {
			 MessageDigest md = MessageDigest.getInstance("SHA-256");
		     md.update(text);
		     return md.digest();
		 } catch (Exception e) {
		     return null;
		 }
	}
	
	static String Digest(String text){
		 try {
			 MessageDigest md = MessageDigest.getInstance("SHA-256");
		     md.update(text.getBytes());
		     byte []dgBytes = md.digest();
		     return new BASE64Encoder().encode(dgBytes);
		 } catch (Exception e) {
		     return null;
		 }
	}
}
