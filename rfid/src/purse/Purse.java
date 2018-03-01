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
	
	private KeyFile keyfile;            //密钥文件
	private BinaryFile cardfile;       //应用基本文件
	private BinaryFile personfile;     //持卡人基本文件
	private EPFile EPfile;              //电子钱包文件 Electronic Purse
	
	public Purse(byte[] bArray, short bOffset, byte bLength){
		papdu = new Papdu();
		
		byte aidLen = bArray[bOffset];
		if(aidLen == (byte)0x00)
			register();
		else
			register(bArray, (short)(bOffset + 1), aidLen);//注册applet
	}
	//安装applet
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Purse(bArray, bOffset, bLength);
	}
	//执行applet
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}		
		//步骤1:取APDU缓冲区数组引用并将之赋给新建数组
		byte buffer[] = apdu.getBuffer();
		//步骤2：取APDU缓冲区中数据放到变量papdu
		short lc = apdu.setIncomingAndReceive();//将apdu读取到卡片缓冲区当中并返回data段的长度
		papdu.cla = buffer[ISO7816.OFFSET_CLA];
		papdu.ins = buffer[ISO7816.OFFSET_INS];
		papdu.p1 = buffer[ISO7816.OFFSET_P1];
		papdu.p2 = buffer[ISO7816.OFFSET_P2];
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, lc);
		//步骤3：判断命令APDU是否包含数据段，有数据则获取数据长度，并对le赋值，
		if(papdu.APDUContainData())//若papdu命令包含数据块
		{
			papdu.le = buffer[ISO7816.OFFSET_CDATA+lc];
			papdu.lc = buffer[ISO7816.OFFSET_LC];
		}
		else
		{
			papdu.le = buffer[ISO7816.OFFSET_LC];//若没data部分则lc部分实际是le
			papdu.lc = 0;
		}
		boolean rc = handleEvent();
		//步骤4:判断是否需要返回数据，并设置apdu缓冲区	
		if(papdu.le != 0)
		{
			Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buffer, ISO7816.OFFSET_CDATA, (short)papdu.pdata.length);
			apdu.setOutgoingAndSend((short)5, papdu.le);//把缓冲区的数据返回给终端
		}
	}

	/*
	 * 功能：对命令的分析和处理
	 * 参数：无
	 * 返回：是否成功处理了命令
	 */
	private boolean handleEvent(){
		switch(papdu.ins){
			case condef.INS_CREATE_FILE:       	return create_file();
			//todo：完成写二进制命令，读二进制命令，写密钥命令
			case condef.INS_WRITE_KEY:			return write_key();
			case condef.INS_WRITE_BIN:			return write_bin();
			case condef.INS_READ_BIN:			return read_bin();
			case condef.INS_NIIT_TRANS:
				if(papdu.p1 == (byte)0x00)		return init_load();
				if(papdu.p1 == (byte)0x01)		return init_purchase();
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//else抛出异常
			case condef.INS_LOAD:				return load();
			case condef.INS_PURCHASE:			return purchase();
			case condef.INS_GET_BALANCE:		return get_balance();
		}	
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		return false;
	}
	/*
	 * 功能：创建文件
	 */
	private boolean create_file() {
		switch(papdu.pdata[0]){ //data的第一位表示要创建文件的类型            
		case condef.EP_FILE:        return EP_file();  
		//todo:完成创建密钥文件，持卡人基本文件和应用基本文件
		case condef.KEY_FILE:		return Key_file();
		case condef.CARD_FILE:		return Card_file();
		case condef.PERSON_FILE:	return Person_file();
		default: 
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		return true;
	}
	/*
	 * 功能：创建电子钱包文件
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
	//创建密钥文件
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
	//创建应用基本文件
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
	//创建持卡人信息文件
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
	//写入一条密钥
	private boolean write_key()
	{
		if(keyfile == null)//都还没密钥文件
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
	//写入二进制文件
	private boolean write_bin()
	{
		if(keyfile == null)//都还没密钥文件
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		//都还没二进制文件--没找到
		if(cardfile == null && papdu.p1 == (byte)0x16)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		if(personfile == null && papdu.p1 == (byte)0x17)
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		
		if(papdu.cla != (byte)0x00)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

	
		if(papdu.lc == 0)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		//写入一条二进制命令到文件
		if(papdu.p1 == (byte)0x16)//表明写入的是应用信息
			this.cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		else if(papdu.p1 == (byte)0x17)//表明写入的是持卡人信息
			this.personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
		
		return true;
	}
	//读取二进制文件
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
		
		
		//读取相应的二进文件
		if(papdu.p1 == (byte)0x16)//表明读取的是应用文件
			this.cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		else if(papdu.p1 == (byte)0x17)//表明读取的是持卡人信息文件
			this.personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
		
		return true;
	}

	/*
	 * 功能：圈存初始化命令的实现
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
		
		num = keyfile.findkey(papdu.pdata[0]);//根据密钥标识寻找密钥返回密钥的记录号
		
		if(num == 0x00)//表示找不到相应密钥
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4load(num, papdu.pdata);//返回0表示成功,返回2表示超额
		
		if(rc == 2)
			ISOException.throwIt((condef.SW_LOAD_FULL));
		
		papdu.le = (short)16;
		
		return true;
	}
	/*
	 * 功能：圈存命令的实现
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
		
		if(rc == 1)//MAC2验证未通过
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_LOAD_FULL);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)4;
		
		return true;
	}
	/*
	 * 功能：消费初始化的实现
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
		
		num = keyfile.findkey(papdu.pdata[0]);//根据tag寻找密钥返回密钥的记录号
		
		if(num == 0x00)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		rc = EPfile.init4purchase(num, papdu.pdata);//返回0表示成功,返回2表示余额不足
		
		if(rc == 2)
			ISOException.throwIt(condef.SW_INSUFFICIENT_ACCOUNT_BALANCE);
		
		papdu.le = (short)15;
		
		return true;
	}
	/*
	 * 功能：消费命令的实现
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
		
		if(rc == 1)//MAC1验证未通过
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		else if(rc == 2)
			ISOException.throwIt(condef.SW_INSUFFICIENT_ACCOUNT_BALANCE);
		else if(rc == 3)
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		
		papdu.le = (short)8;
		
		return true;
	}
	/*
	 * 功能：余额查询功能的实现
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
			Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);//余额
		
		papdu.le = (short)0x04;
		
		return true;
	}
	
}
