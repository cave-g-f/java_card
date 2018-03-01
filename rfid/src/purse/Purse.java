package purse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Purse extends Applet {
	//APDU Object
	private Papdu papdu;
	
	private KeyFile keyfile;            //��Կ�ļ�
	private BinaryFile cardfile;       //Ӧ�û����ļ�
	private BinaryFile personfile;     //�ֿ��˻����ļ�
	private EPFile EPfile;              //����Ǯ���ļ� Electronic Purse
	
	public Purse(byte[] bArray, short bOffset, byte bLength){
		papdu = new Papdu();
		
		byte aidLen = bArray[bOffset];
		if(aidLen == (byte)0x00)
			register();
		else
			register(bArray, (short)(bOffset + 1), aidLen);//ע��applet
	}
	//��װapplet
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Purse(bArray, bOffset, bLength);
	}
	//ִ��applet
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}		
		//����1:ȡAPDU�������������ò���֮�����½�����
		byte buffer[] = apdu.getBuffer();
		//����2��ȡAPDU�����������ݷŵ�����papdu
		short lc = apdu.setIncomingAndReceive();//��apdu��ȡ����Ƭ���������в�����data�εĳ���
		papdu.cla = buffer[ISO7816.OFFSET_CLA];
		papdu.ins = buffer[ISO7816.OFFSET_INS];
		papdu.p1 = buffer[ISO7816.OFFSET_P1];
		papdu.p2 = buffer[ISO7816.OFFSET_P2];
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, lc);
		//����3���ж�����APDU�Ƿ�������ݶΣ����������ȡ���ݳ��ȣ�����le��ֵ��
		if(papdu.APDUContainData())//��papdu����������ݿ�
		{
			papdu.le = buffer[ISO7816.OFFSET_CDATA+lc];
			papdu.lc = buffer[ISO7816.OFFSET_LC];
		}
		else
		{
			papdu.le = buffer[ISO7816.OFFSET_LC];//��ûdata������lc����ʵ����le
			papdu.lc = 0;
		}
		boolean rc = handleEvent();
		//����4:�ж��Ƿ���Ҫ�������ݣ�������apdu������	
		if(papdu.le != 0)
		{
			Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buffer, ISO7816.OFFSET_CDATA, (short)papdu.pdata.length);
			apdu.setOutgoingAndSend((short)5, papdu.le);//�ѻ����������ݷ��ظ��ն�
		}
	}

	/*
	 * ���ܣ�������ķ����ʹ���
	 * ��������
	 * ���أ��Ƿ�ɹ�����������
	 */
	private boolean handleEvent(){
		switch(papdu.ins){
			case condef.INS_CREATE_FILE:       	return create_file();
			//todo�����д��������������������д��Կ����
			case condef.INS_WRITE_KEY:			return write_key();
			case condef.INS_WRITE_BIN:			return write_bin();
			case condef.INS_READ_BIN:			return read_bin();
			case condef.INS_NIIT_TRANS:
				if(papdu.p1 == (byte)0x00)		return init_load();
				if(papdu.p1 == (byte)0x01)		return init_purchase();
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//else�׳��쳣
			case condef.INS_LOAD:				return load();
			case condef.INS_PURCHASE:			return purchase();
			case condef.INS_GET_BALANCE:		return get_balance();
		}	
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		return false;
	}
	/*
	 * ���ܣ������ļ�
	 */
	private boolean create_file() {
		switch(papdu.pdata[0]){ //data�ĵ�һλ��ʾҪ�����ļ�������            
		case condef.EP_FILE:        return EP_file();  
		//todo:��ɴ�����Կ�ļ����ֿ��˻����ļ���Ӧ�û����ļ�
		case condef.KEY_FILE:		return Key_file();
		case condef.CARD_FILE:		return Card_file();
		case condef.PERSON_FILE:	return Person_file();
		default: 
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		return true;
	}
	/*
	 * ���ܣ���������Ǯ���ļ�
	 */
	private boolean EP_file() {
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(keyfile == null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		this.EPfile = new EPFile(keyfile);
		
		return true;
	}
	//������Կ�ļ�
	private boolean Key_file()
	{
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(keyfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		this.keyfile = new KeyFile();
		
		return true;
	}
	//����Ӧ�û����ļ�
	private boolean Card_file()
	{
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(cardfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(keyfile == null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		this.cardfile = new BinaryFile(papdu.pdata);
		
		return true;
	}
	//�����ֿ�����Ϣ�ļ�
	private boolean Person_file()
	{
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.lc != (byte)0x07)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(personfile != null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(keyfile == null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		this.personfile = new BinaryFile(papdu.pdata);
		
		return true;
	}
	//д��һ����Կ
	private boolean write_key()
	{
		if(keyfile == null)//����û��Կ�ļ�
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		
		if(papdu.p2 != (byte)0x06 && papdu.p2 != (byte)0x07 && papdu.p2 != (byte)0x08)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	
		if(papdu.lc == 0 || papdu.lc > 21)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(keyfile.recNum >= 3)
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		
		this.keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
		
		return true;
	}
	//д��������ļ�
	private boolean write_bin()
	{
		if(keyfile == null)//����û��Կ�ļ�
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		//����û�������ļ�--û�ҵ�
		if(cardfile == null && papdu.p1 == (byte)0x16)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(personfile == null && papdu.p1 == (byte)0x17)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

	
		if(papdu.lc == 0)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		//д��һ������������ļ�
		if(papdu.p1 == (byte)0x16)//����д�����Ӧ����Ϣ
			this.cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		else if(papdu.p1 == (byte)0x17)//����д����ǳֿ�����Ϣ
			this.personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		
		return true;
	}
	//��ȡ�������ļ�
	private boolean read_bin()
	{
		if(keyfile == null)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		

		if(cardfile == null && papdu.p1 == (byte)0x16)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(personfile == null && papdu.p1 == (byte)0x17)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		
		//��ȡ��Ӧ�Ķ����ļ�
		if(papdu.p1 == (byte)0x16)//������ȡ����Ӧ���ļ�
			this.cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		else if(papdu.p1 == (byte)0x17)//������ȡ���ǳֿ�����Ϣ�ļ�
			this.personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		
		return true;
	}

	/*
	 * ���ܣ�Ȧ���ʼ�������ʵ��
	 */
	private boolean init_load() {
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);//������Կ��ʶѰ����Կ������Կ�ļ�¼��
		
		if(num == 0x00)//��ʾ�Ҳ�����Ӧ��Կ
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4load(num, papdu.pdata);//����0��ʾ�ɹ�,����2��ʾ����
		
		if(rc == 2)
			ISOException.throwIt((condef.SW_LOAD_FULL));
		
		papdu.le = (short)16;
		
		return true;
	}
	/*
	 * ���ܣ�Ȧ�������ʵ��
	 */
	private boolean load() {
		short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		rc = EPfile.load(papdu.pdata);
		
		if(rc == 1)//MAC2��֤δͨ��
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_LOAD_FULL);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)4;
		
		return true;
	}
	/*
	 * ���ܣ����ѳ�ʼ����ʵ��
	 */
	private boolean init_purchase(){
		
		short num,rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(papdu.lc != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		num = keyfile.findkey(papdu.pdata[0]);//����tagѰ����Կ������Կ�ļ�¼��
		
		if(num == 0x00)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4purchase(num, papdu.pdata);//����0��ʾ�ɹ�,����2��ʾ����
		
		if(rc == 2)
			ISOException.throwIt(condef.SW_INSUFFICIENT_ACCOUNT_BALANCE);
		
		papdu.le = (short)15;
		
		return true;
	}
	/*
	 * ���ܣ����������ʵ��
	 */
	private boolean purchase(){
		short rc;
		
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		if(EPfile == null)
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		if(papdu.lc != (short)0x0F)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		rc = EPfile.purchase(papdu.pdata);
		
		if(rc == 1)//MAC1��֤δͨ��
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_INSUFFICIENT_ACCOUNT_BALANCE);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)8;
		
		return true;
	}
	/*
	 * ���ܣ�����ѯ���ܵ�ʵ��
	 */
	private boolean get_balance(){
		if(papdu.cla != (byte)0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		
		short result;
		byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		result = EPfile.get_balance(balance);
		
		if(result == (short)0)
			Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);//���
		
		papdu.le = (short)0x04;
		
		return true;
	}
	
}
