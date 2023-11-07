package tonwallet ;

import org.globalplatform.GPSystem;

public class Constants  
{    
    // App states
    public static final byte APP_INSTALLED = (byte) GPSystem.APPLICATION_SELECTABLE;
    public static final byte APP_WAITE_AUTHORIZATION_MODE = (byte) 0x27;
    public static final byte APP_PERSONALIZED = (byte) 0x17;   
    public static final byte APP_DELETE_KEY_FROM_KEYCHAIN_MODE = (byte) 0x37;  
    public static final byte APP_BLOCKED_MODE = (byte) 0x47;
    	
	public static final short COMMON_SECRET_SIZE = 32;
	public static final short SHA_HASH_SIZE = (short) 32;
	public static final short HMAC_SIG_SIZE = (short) 32;	
	public static final short SAULT_SIZE = 32;	
	public final static short MAX_IND_SIZE = (short) 10;
	public final static short SERIAL_NUMBER_SIZE = (short) 24;
	
	public static final short DATA_CHUNK_MAX_SIZE = (short) 189; 
	public static final short DATA_FOR_SIGNING_MAX_SIZE = (short) 189; 
	public static final short DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH = (short) 178;
	
	public static final byte MAX_PIN_TRIES_NUM = (byte) 10;
}
