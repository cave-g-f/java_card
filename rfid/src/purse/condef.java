package purse;
/**
 * �Ѹ������ֳ���ֵ������������Ҫ������� 
 */
public class condef {
	//----------------- INS Byte -------------------
	final static byte INS_CREATE_FILE     = (byte)0xE0;         //�ļ����������INSֵ
	final static byte INS_WRITE_KEY       = (byte)0xD4;         //д����Կ�����INSֵ
	final static byte INS_WRITE_BIN       = (byte)0xD6;         //д������������INSֵ
	final static byte INS_NIIT_TRANS      = (byte)0x50;         //��ʼ��Ȧ��ͳ�ʼ�����������INSֵ
	final static byte INS_LOAD            = (byte)0x52;         //Ȧ�������INSֵ
	final static byte INS_READ_BIN		  = (byte)0xB0;			//��ȡ�����������INSֵ
	final static byte INS_PURCHASE		  = (byte)0x54;         //���������INSֵ
	final static byte INS_GET_BALANCE     = (byte)0x5C;         //��ѯ���
	
	//������������������������������FILE TYPE Byte ---------------
	final static byte KEY_FILE            = (byte)0x3F;         //��Կ�ļ����ļ�����
	final static byte CARD_FILE           = (byte)0x38;         //Ӧ�û����ļ����ļ�����
	final static byte PERSON_FILE         = (byte)0x39;         //�ֿ��˻����ļ� ���ļ�����
	final static byte EP_FILE             = (byte)0x2F;         //����Ǯ���ļ����ļ�����
	
	//------------------------ SW --------------------- 
	final static short SW_LOAD_FULL = (short)0x9501;      //Ȧ�泬��	
	final static short SW_INSUFFICIENT_ACCOUNT_BALANCE = (short)0x9401; //����
}
