package tonwallet ;

import static tonwallet.Constants.*;
import static tonwallet.ErrorCodes.*;
import javacard.security.*;
import javacard.framework.*;

public class SaultHandler  
{
	private byte[] sault;
	
	private RandomData rd;
	
	private static SaultHandler saultHandler;
	
	public static SaultHandler getInstance() {
		if (saultHandler == null)
			saultHandler = new SaultHandler();
		return saultHandler;
	}
	
	private SaultHandler() {
		sault = new byte[SAULT_SIZE];
		rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		generateNewSault();
	}
			
	public boolean compareSault(byte[] buf, short offset){
		if (offset < 0) {
			ISOException.throwIt(SW_INCORRECT_OFFSET);
		}
		if (buf == null || ((short) (buf.length - offset) < (short) sault.length)) {
			ISOException.throwIt(SW_INTERNAL_BUFFER_IS_NULL_OR_TOO_SMALL);
		}				
		boolean res = Util.arrayCompare(sault, (short) 0x00, 
					buf, offset, (short) sault.length) == 0x00;	
					
		generateNewSault();
			
		return res;			
	}
	
	public void getSault(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short le = apdu.setOutgoing();
		if (le != (short) sault.length) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		Util.arrayCopyNonAtomic(sault, (short) 0x00, 
			buffer, (short) 0x00, SAULT_SIZE);
							   
		apdu.setOutgoingLength((short) sault.length);   
		apdu.sendBytes((short) 0x00, (short) sault.length);
	}
	
	private void generateNewSault() {
		rd.generateData(sault, (short) 0x00, (short) sault.length);
	}		
}


