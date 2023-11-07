package tonwallet ;

import javacard.framework.*;
import javacard.security.*;
import static tonwallet.Constants.*;
import javacardx.crypto.*;

public class CommonSecretHandler  
{	
	private byte[] decryptedCommonSecret;
	private byte[] encryptedCommonSecret;
	
	private boolean isEncryptedCommonSecretSet = false;
	
	private MessageDigest md;
	
	private Cipher cipherDec;
	private AESKey aesKey;
	
	private static CommonSecretHandler commonSecretHandler;
	
	public static CommonSecretHandler getInstance() {
		if (commonSecretHandler == null)
			commonSecretHandler = new CommonSecretHandler();
		return commonSecretHandler;
	}
	
	private CommonSecretHandler() {
		encryptedCommonSecret = new byte[COMMON_SECRET_SIZE];
		decryptedCommonSecret = new byte[COMMON_SECRET_SIZE];
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		cipherDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
	    aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	}
	
	public boolean isEncryptedCommonSecretSet() {
		return isEncryptedCommonSecretSet;
	}
	
	public void setEncryptedCommonSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if((numBytes != byteRead) || (numBytes != COMMON_SECRET_SIZE)) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
									                            		             
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, 
			encryptedCommonSecret, (short) 0x00, COMMON_SECRET_SIZE);
		
		isEncryptedCommonSecretSet = true;    
    }
    
    public void decryptCommonSecret(byte[] aesKeyBytes, byte[] iv, short ivOffset, short ivLen) {
    	aesKey.setKey(aesKeyBytes, (short) 0x00);
        cipherDec.init(aesKey, Cipher.MODE_DECRYPT, iv, 
					ivOffset, ivLen);
	    cipherDec.doFinal(encryptedCommonSecret, (short) 0x00, COMMON_SECRET_SIZE, 
				decryptedCommonSecret, (short) 0x00);
    }
    
    public byte[] getEncryptedCommonSecret() {
	    return encryptedCommonSecret;
    }
    
    public byte[] getCommonSecret() {
	    return decryptedCommonSecret;
    }
    
    public void getHashOfEncryptedCommonSecret(APDU apdu) {
	    byte[] buffer = apdu.getBuffer(); 
	    short le = apdu.setOutgoing();
		if (le != SHA_HASH_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}    
	    md.doFinal(encryptedCommonSecret, (short)0x00, COMMON_SECRET_SIZE, buffer, (short) 0x00);	  					
		apdu.setOutgoingLength(SHA_HASH_SIZE);
		apdu.sendBytes((short) 0x00, SHA_HASH_SIZE);   
    }
}

