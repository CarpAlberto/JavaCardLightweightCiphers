package sid;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public abstract class Sha3Keccak implements IConsts 
{
	protected short KECCAK_VALUE_W;
	protected short KECCAK_STATE_SIZE_BITS;
	protected short KECCAK_NUMBER_OF_ROUNDS;
	protected short KECCAK_SEC_LEVEL = 80;
	protected short PROCESSOR_WORD = 16;
	protected short KECCAK_CAPACITY;
	protected short KECCAK_RATE;
	protected short KECCAK_STATE_SIZE_WORDS;
	protected short KECCAK_RATE_SIZE_WORDS;
	protected short KECCAK_SIZE_BYTES;
	protected short TEMPORARY_MEMORY=128;
	protected byte[] transientMemory = JCSystem.makeTransientByteArray(TEMPORARY_MEMORY, JCSystem.CLEAR_ON_DESELECT);
	protected byte[] transientHash = JCSystem.makeTransientByteArray(TEMPORARY_MEMORY, JCSystem.CLEAR_ON_DESELECT);
	protected byte OFFSET_MESSAGE=0x00;
	
	public class keccack_state_internal {
		public double_uint8[] state = new double_uint8[KECCAK_RATE_SIZE_WORDS]; 
		public byte state_control;
		public byte squeezing_mode;
	};
	
	public class double_uint8{
		public byte msb;
		public byte lsb;
	};
	
	protected keccack_state_internal keccak_state;
	
	abstract void keccak_hash(byte[] message,short message_size,byte[] hash,short hash_size);
	
	public abstract  void postInit();
	
	public static Sha3Keccak getInstance(final byte cipher)
	{
		switch(cipher)
		{
			case IConsts.HASH_KECCAK_160:
				return Sha3Keccak160.getInstance();
		}
		ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);;
		return null;
	}
	
	public short process(byte type,byte[] message,byte message_offset,short message_size)
	{
		Util.arrayCopy(message, message_offset, transientMemory, OFFSET_MESSAGE, message_size);
		keccak_hash(transientMemory,message_size,transientHash,KECCAK_SIZE_BYTES);
		Util.arrayCopy(transientHash,OFFSET_MESSAGE, message, (short) message_offset, KECCAK_SIZE_BYTES);
		return KECCAK_SIZE_BYTES;
		
	}
	
}
