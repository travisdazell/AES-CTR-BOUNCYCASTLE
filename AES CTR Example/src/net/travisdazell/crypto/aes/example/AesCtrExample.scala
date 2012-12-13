package net.travisdazell.crypto.aes.example

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import scala.collection.mutable.ArrayBuffer

object AesCtrExample {
	def bytesToHex(bytes : Array[Byte]) = {
	    val hexArray = List('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F')
	    var hexChars = new Array[Char](bytes.length * 2)
	    var v = 0
	    for (j <- 0 until bytes.length) {
	        v = bytes(j) & 0xFF
	        hexChars(j * 2) = hexArray(v >>> 4)
	        hexChars(j * 2 + 1) = hexArray(v & 0x0F)
	    }
	    
	    new String(hexChars)
	}	

	def convertHexStringToAscii(hexString : String) = {
	  val sb = new StringBuilder();
	  val temp = new StringBuilder();
 
	  //49204c6f7665204a617661 split into two characters 49, 20, 4c...
	  var i = 0
	  while (i < hexString.length - 1) {
	    
	      //grab the hex in pairs
	      val output = hexString.substring(i, (i + 2))

	      //convert hex to decimal
	      val decimal = Integer.parseInt(output, 16)
	      
	      //convert the decimal to character
	      sb.append(decimal.asInstanceOf[Char])
 
	      temp.append(decimal)

	      i+=2
	  }
	  
	  sb.toString()	  
	}
	
	def convertStringToHex(input : String) = {
		val sb = new StringBuilder()
		for (c <- input) {
		  val i = Integer.valueOf(c)
		  if (i < 10) {
		    sb.append("0")
		  }
		  sb.append(Integer.toHexString(i))
		}

		sb.toString()
	}

    def hexStringToByteArray(s : String) = {
		val len = s.length();
		var data = new Array[Byte](len / 2)
    
		var i = 0
		while (i < len) {
			val b = (Character.digit(s.charAt(i), 16) << 4) + (Character.digit(s.charAt(i+1), 16))
			data(i / 2) = b.asInstanceOf[Byte]
      
			i+=2
		}

		data
	}

	def encrypt(hexEncodedIv : String, hexEncodedKey : String, hexEncodedMessage : String) = {
	  // we're using Bouncy Castle
	  Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())

	  // create our key specification
	  val secretKeySpec = new SecretKeySpec(hexStringToByteArray(hexEncodedKey), "AES")
	  
	  // create an AES engine in CTR mode (no padding)
	  val aes = Cipher.getInstance("AES/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME)
	  
	  // initialize the AES engine in encrypt mode with the key and IV
	  aes.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(hexStringToByteArray(hexEncodedIv)))
	  
	  // encrypt the message and return the encrypted byte array
	  aes.doFinal(hexStringToByteArray(hexEncodedMessage))
	}
	
	def decrypt(hexEncodedIv : String, hexEncodedKey : String, hexEncodedCipherText : String) = {
	  // we're using Bouncy Castle
	  Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())

	  // create our key specification
	  val secretKeySpec = new SecretKeySpec(hexStringToByteArray(hexEncodedKey), "AES")
	  
	  // create an AES engine in CTR mode (no padding)
	  val aes = Cipher.getInstance("AES/CTR/NoPadding", BouncyCastleProvider.PROVIDER_NAME)
	  
	  // initialize the AES engine in decrypt mode with the key and IV
	  aes.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(hexStringToByteArray(hexEncodedIv)))
	  
	  // decrypt the ciphertext and return the plaintext as a byte array
	  aes.doFinal(hexStringToByteArray(hexEncodedCipherText))
	}
	
	def main(args : Array[String]) {
	  val message = "Welcome to my blog. I hope this tutorial was helpful."
	  val key =     "140b41b22a29beb4061bda66b6747e14"
	  val iv = "20814804c1767293bd9f1d9cab3bc3e7"
	  
	  val encrypted = encrypt(iv, key, convertStringToHex(message))
	  val ciphertext = bytesToHex(encrypted)
	  println(ciphertext)
	  
	  val decrypted = decrypt(iv, key, ciphertext)
	  println(convertHexStringToAscii(bytesToHex(decrypted)))
	}
}