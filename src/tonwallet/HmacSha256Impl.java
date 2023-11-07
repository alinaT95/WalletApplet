package tonwallet ;

import javacard.framework.*;
import javacard.security.*;
import static tonwallet.Constants.*;
import static tonwallet.ErrorCodes.*;

public class HmacSha256Impl  
{
	public static final short LEN_HMAC_BLOCK = 64;     
    public static final short KEY_SIZE = HMAC_SIG_SIZE;
    
    private static final byte ipad = 0x36;
	private static final byte opad = 0x5C;
	
	private byte[] tmpBuffer;
	private byte[] ipadK;
	private byte[] opadK;
	
	private MessageDigest md;	
	
	private static HmacSha256Impl hmacSha256Impl;
	
	public static HmacSha256Impl getInstance(){
		if (hmacSha256Impl == null)
			hmacSha256Impl = new HmacSha256Impl();
		return hmacSha256Impl;
	}
	
	private HmacSha256Impl(){
		try {
            tmpBuffer = JCSystem.makeTransientByteArray(LEN_HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
            tmpBuffer = new byte[LEN_HMAC_BLOCK];
		} 
		
		try {
            ipadK = JCSystem.makeTransientByteArray(LEN_HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
            ipadK = new byte[LEN_HMAC_BLOCK];
		} 
		
		try {
            opadK = JCSystem.makeTransientByteArray(LEN_HMAC_BLOCK, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
            opadK = new byte[LEN_HMAC_BLOCK];
		}
		
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);	
	}
	
	public short sign(byte[] key, short keyOffset,  
							byte[] msg, short msgOffset, short msgLength,
							byte[] mac, short macOffset) {				
		if (msgLength <= 0){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }        
        if (keyOffset < 0 || macOffset < 0 || msgOffset < 0){
            ISOException.throwIt(SW_INCORRECT_OFFSET);
        }		
		if (key == null || ((short)(key.length - keyOffset) < KEY_SIZE) 
			|| mac == null || ((short)(mac.length - macOffset) < HMAC_SIG_SIZE) 
			|| msg == null || ((short)(msg.length - msgOffset) < msgLength)){
			 ISOException.throwIt(SW_INTERNAL_BUFFER_IS_NULL_OR_TOO_SMALL);	
		}
		
		Util.arrayCopyNonAtomic(key, keyOffset, tmpBuffer, (short) 0x00, KEY_SIZE);
		
		for (short i = 0x00; i < LEN_HMAC_BLOCK; i++)
		{
			// for each byte of the key, work out the pad byte
			if (i >= KEY_SIZE)
			{
				ipadK[i] = (byte) (0x00 ^ ipad);
				opadK[i] = (byte) (0x00 ^ opad);
			}
			else
			{
				ipadK[i] = (byte) (tmpBuffer[i] ^ ipad);
				opadK[i] = (byte) (tmpBuffer[i] ^ opad);
			}
		}

		// clear the tmpBuffer - it can be used now for digest outputs
		Util.arrayFillNonAtomic(tmpBuffer, (short) 0x00, KEY_SIZE, (byte)0x00);

		// find H(ipadK || msg)
        md.reset();
        md.update(ipadK, (short) 0x00, LEN_HMAC_BLOCK);
        md.doFinal(msg, msgOffset, msgLength, tmpBuffer, (short) 0x00);

		//now find H(opadK || tmpBuffer)
		md.reset();
        md.update(opadK, (short) 0x00, LEN_HMAC_BLOCK);
		short outputLength;
		outputLength = md.doFinal(tmpBuffer, (short) 0x00, KEY_SIZE, mac, macOffset);
		md.reset();
		// clear the tmpBuffer
		Util.arrayFillNonAtomic(tmpBuffer, (short) 0x00, KEY_SIZE, (byte) 0x00);
		return outputLength;
	}

}

