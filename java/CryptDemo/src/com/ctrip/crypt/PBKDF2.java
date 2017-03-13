package com.ctrip.crypt;

import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 {
	static byte [] DeriveKey(String password){
		try {
			byte[] salt = new byte[8];
			Random ran = new Random();
			ran.nextBytes(salt);		//8字节随机盐

            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 2048, 128);		//1024次迭代，128位（16字节）
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey secret = factory.generateSecret(spec);
            byte []pbkdf2 = secret.getEncoded();
            
            //将盐和pbkdf2值拼接后返回
            byte []all = new byte[salt.length + pbkdf2.length];
            System.arraycopy(salt, 0, all, 0, salt.length);
			System.arraycopy(pbkdf2, 0, all, salt.length, pbkdf2.length);
            
            return all;
        }catch (Exception e) {
                e.printStackTrace();
            return null;
        }
	}

	static boolean Verify(String password, byte []pbkdf2){
		try {
			byte[] salt = new byte[8];
			byte[] pb = new byte[pbkdf2.length - 8];
	
	        System.arraycopy(pbkdf2, 0, salt, 0, salt.length);
			System.arraycopy(pbkdf2, salt.length, pb, 0, pb.length);
	
	        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 128);		//1024次迭代，128位（16字节）
	        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	        SecretKey secret = factory.generateSecret(spec);
	        
	        return Arrays.equals(secret.getEncoded(), pb);
		}catch (Exception e) {
            e.printStackTrace();
        return false;
    }
	}
}
