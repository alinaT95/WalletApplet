package tonwallet ;

public class ErrorCodes  
{
	// Common errors
		
	public final static short SW_INTERNAL_BUFFER_IS_NULL_OR_TOO_SMALL  = (short) 0x4F00;
	
	public final static short SW_PERSONALIZATION_NOT_FINISHED  = (short) 0x4F01;
	
	public final static short SW_INCORRECT_OFFSET = (short) 0x4F02;
	
	public final static short SW_INCORRECT_PAYLOAD = (short) 0x4F03;
	
	// Password authentication errors
	public final static short SW_INCORRECT_PASSWORD_FOR_CARD_AUTHENICATION   = (short) 0x5F00;
    
    public final static short SW_INCORRECT_PASSWORD_CARD_IS_BLOCKED   = (short) 0x5F01;
    
       
    // Signature errors    
    public final static short SW_SET_COIN_TYPE_FAILED = (short) 0x6F01;
    
    public final static short SW_SET_CURVE_FAILED = (short) 0x6F02;
    
    public final static short SW_GET_COIN_PUB_DATA_FAILED = (short) 0x6F03;
    
    public final static short SW_SIGN_DATA_FAILED = (short) 0x6F04;
       
    // Pin verification errors
    
    public final static short SW_INCORRECT_PIN = (short) 0x6F07;
    
    public final static short SW_PIN_TRIES_EXPIRED = (short) 0x6F08;
    
    // Recovery errors
    
    public final static short SW_RECOVERY_DATA_TOO_LONG = (short) 0x6F09;
    
    public final static short SW_INCORRECT_START_POS_OR_LE = (short) 0x6F0A;
    
    public final static short SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED = (short) 0x6F0B;
    
    public final static short SW_RECOVERY_DATA_ALREADY_EXISTS = (short) 0x6F0C;
    
    public final static short SW_RECOVERY_DATA_IS_NOT_SET = (short) 0x6F0D;
    
    
    // Key chain errors
    
    public final static short SW_INCORRECT_KEY_INDEX  = (short) 0x7F00;
      
    public final static short SW_INCORRECT_KEY_CHUNK_START_OR_LEN  = (short) 0x7F01;
    
    public final static short SW_INCORRECT_KEY_CHUNK_LEN  = (short) 0x7F02;

    public final static short SW_NOT_ENOUGH_SPACE = (short) 0x7F03;
       
    public final static short SW_KEY_SIZE_UNKNOWN  = (short) 0x7F04;
	
	public final static short SW_KEY_LEN_INCORRECT  = (short) 0x7F05;
	
	public final static short SW_HMAC_EXISTS   = (short) 0x7F06;
	
	public final static short SW_INCORRECT_KEY_INDEX_TO_CHANGE  = (short) 0x7F07;
	
	public final static short SW_MAX_KEYS_NUMBER_EXCEEDED  = (short) 0x7F08;
	
	public final static short SW_DELETE_KEY_CHUNK_IS_NOT_FINISHED  = (short) 0x7F09;
	
	
	// Hmac errors
			
	public final static short SW_INCORRECT_SAULT   = (short) 0x8F01;
			
	public final static short SW_DATA_INTEGRITY_CORRUPTED  = (short) 0x8F02;

    public final static short SW_INCORRECT_APDU_HMAC  = (short) 0x8F03;
    
    public final static short SW_HMAC_VERIFICATION_TRIES_EXPIRED   = (short) 0x8F04;
    
    // Serial number errors
    
    public final static short SW_SERIAL_NUMBER_IS_NOT_SET    = (short) 0xA001;
    public final static short SW_SERIAL_NUMBER_INCORRECT_FORMAT = (short) 0xA002;
}

