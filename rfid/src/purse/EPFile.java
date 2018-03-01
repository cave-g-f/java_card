package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EPFile {
	private KeyFile keyfile;
	
	//内部数据元
	private byte[] EP_balance;         //电子钱包余额
	private byte[] EP_offline;         //电子钱包联机交易序号
	private byte[] EP_online;          //电子钱包脱机交易序号
	
	byte keyID;        //密钥版本号
	byte algID;        //算法标识符
	
	//安全系统设计
	private Randgenerator RandData;          //随机数产生
	private PenCipher EnCipher;              //数据加解密方式实现
/**
 * 下面数据是计算时需要用到的临时过程数据	
 */
	//临时计算数据
	//4个字节的临时计算数据
	private byte[] pTemp41;           
	private byte[] pTemp42;
	
	//8个字节的临时计算数据
	private byte[] pTemp81;
	private byte[] pTemp82;
	
	//32个字节的临时计算数据
	private byte[] pTemp16;
	private byte[] pTemp32;
	
	public EPFile(KeyFile keyfile){
		EP_balance = new byte[4];
		Util.arrayFillNonAtomic(EP_balance, (short)0, (short)4, (byte)0x00);//初始化语句
		
		EP_offline = new byte[2];
		Util.arrayFillNonAtomic(EP_offline, (short)0, (short)2, (byte)0x00);
		
		EP_online = new byte[2];
		Util.arrayFillNonAtomic(EP_online, (short)0, (short)2, (byte)0x00);
		
		this.keyfile = keyfile;
		
		pTemp41 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		pTemp42 = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		
		pTemp81 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		pTemp82 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		
		pTemp16 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		pTemp32 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		
		RandData = new Randgenerator();
		EnCipher = new PenCipher();
	}
	
	/*
	 * 功能：电子钱包金额的增加
	 * 参数：data 所增加的金额  
	 * 	   flag 是否真正增加电子钱包余额
	 * 返回：圈存后，余额是否超过最大限额
	 */
	public final short increase(byte[] data, boolean flag){
		short i, t1, t2, ads;
		
		ads = (short)0;
		for(i = 3; i >= 0; i --){
			t1 = (short)(EP_balance[(short)i] & 0xFF);
			t2 = (short)(data[i] & 0xFF);
			
			t1 = (short)(t1 + t2 + ads);
			if(flag)
				EP_balance[(short)i] = (byte)(t1 % 256);
			ads = (short)(t1 / 256);
		}
		return ads;
	}
	
	/*
	 * 功能：圈存初始化功能完成
	 * 参数：num 密钥记录号， data 命令报文中的数据段
	 * 返回：0： 圈存初始化命令执行成功     2：圈存超过电子钱包最大限额
	 */
	public final short init4load(short num, byte[] data){
		short length,rc;
		
		Util.arrayCopyNonAtomic(data, (short)1, pTemp42, (short)0, (short)4);  //交易金额
		Util.arrayCopyNonAtomic(data, (short)5, pTemp81, (short)0, (short)6);  //终端机编号
		
		//判断是否超额圈存
		rc = increase(pTemp42, false);
		if(rc != (short)0)
			return (short)2;
		
		//密钥获取
		length = keyfile.readkey(num, pTemp32);
		keyID = pTemp32[3];
		algID = pTemp32[4];
		Util.arrayCopyNonAtomic(pTemp32, (short)5, pTemp16, (short)0, length);
		
		//产生随机数
		RandData.GenerateSecureRnd();
		RandData.getRndValue(pTemp32, (short)0);//产生随机数
		
		//产生过程密钥
		Util.arrayCopyNonAtomic(EP_online, (short)0, pTemp32, (short)4, (short)2);//交易序列号EP_online
		pTemp32[6] = (byte)0x80;
		pTemp32[7] = (byte)0x00;
		
		EnCipher.gen_SESPK(pTemp16, pTemp32, (short)0, (short)8, pTemp82, (short)0); //过程密钥
		
		//产生MAC1
		Util.arrayCopyNonAtomic(EP_balance, (short)0, pTemp32, (short)0, (short)4);   //电子钱包余额
		Util.arrayCopyNonAtomic(data, (short)1, pTemp32, (short)4, (short)4);         //交易金额
		pTemp32[8] = (byte)0x02;                                                      //交易类型标识
		Util.arrayCopyNonAtomic(data, (short)5, pTemp32, (short)9, (short)6);         //终端机编号
		EnCipher.gmac4(pTemp82, pTemp32, (short)0x0F, pTemp41);
		
		//返回响应数据,全部在这赋值了
		Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);      //电子钱包余额
		Util.arrayCopyNonAtomic(EP_online, (short)0, data,  (short)4, (short)2);      //电子钱包联机交易序号
		data[6] = keyID;                                                              //密钥版本号
		data[7] = algID;                                                              //算法标识
		RandData.getRndValue(data, (short)8);                                         //随机数
		Util.arrayCopyNonAtomic(pTemp41, (short)0, data, (short)12, (short)4);        //mac1
			
		return 0;
	}
	
	/*
	 * 功能：圈存功能的完成
	 * 参数：data 命令报文中的数据段
	 * 返回：0 圈存命令执行成功；1 MAC2校验错误；  2 圈存超过最大限额; 3 密钥未找到
	 */
	public final short load(byte[] data){
		short rc;
		
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       //交易金额
		pTemp32[4] = (byte)0x02;                                                       //交易标识
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);       //终端机编号
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)11, (short)7);         //交易日期与时间
		
		EnCipher.gmac4(pTemp82, pTemp32, (short)18, pTemp41);
		
	
		if(Util.arrayCompare(data, (short)7, pTemp41, (short)0, (short)4) != (byte)0x00)
			return (short)1;
		
		//电子钱包数目增加
		rc = increase(pTemp42, true);
		if(rc != (short)0)
			return (short)2;
		
		//TAC数据
		Util.arrayCopyNonAtomic(EP_balance, (short)0, pTemp32, (short)0, (short)4);    //电子钱包余额
		Util.arrayCopyNonAtomic(EP_online, (short)0, pTemp32, (short)4, (short)2);     //电子钱包联机交易序号
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)6, (short)4);       //交易金额
		pTemp32[10] = (byte)0x02;                                                      //交易类型
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)11, (short)6);      //终端机编号
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)17, (short)7);         //交易日期与时间
		
		//联机交易序号加1
		rc = Util.makeShort(EP_online[0], EP_online[1]);
		rc ++;
		if(rc > (short)256)
			rc = (short)1;
		Util.setShort(EP_online, (short)0, rc);
		
		//TAC的计算
		short length, num;
		num = keyfile.findKeyByType((byte)0x34);
		length = keyfile.readkey(num, pTemp16);
		
		if(length == 0)
			return (short)3;
		
		Util.arrayCopyNonAtomic(pTemp16, (short)5, pTemp82, (short)0, (short)8);
		
		EnCipher.xorblock8(pTemp82, pTemp16, (short)13);
		
		byte[] temp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(pTemp16, (short)13, temp, (short)0, (short)8);
		
		
		EnCipher.gmac4(temp, pTemp32, (short)0x18, data);
		
		return (short)0;
	}
		/*
	 * 功能：电子钱包金额减少
	 * 参数：data 消费的金额； flag 是否真正扣减电子钱包余额
	 * 返回： 消费是否超额
	 */
	public final short decrease(byte[] data, boolean flag){
		short i, t1, t2, ads;
		ads = (short)0;
		for(i = 3; i >= 0; i--){
			t1 = (short)(EP_balance[(short)i] & 0xFF);
			t2 = (short)(data[i] & 0xFF);
			
			if(t2 > t1)
				ads = (short)1;
			t1 = (short)(t1 - t2 - ads);
			if(flag)
				EP_balance[(short)i] = (byte)(t1 % 256);
		}
		
		return ads;
	}
		
	/*
	 * 功能：消费初始化命令的完成
	 * 参数：num 密钥记录号； data 命令报文中的数据段
	 * 返回：0 命令执行成功；2 消费超额
	 */
	public final short init4purchase(short num, byte[] data){
		short length,rc;
		
		Util.arrayCopyNonAtomic(data, (short)1, pTemp42, (short)0, (short)4);  //交易金额
		Util.arrayCopyNonAtomic(data, (short)5, pTemp81, (short)0, (short)6);  //终端机编号
		
		//判断余额是否足够
		rc = decrease(pTemp42, false);
		if(rc != (short)0)
			return (short)2;
		
		//密钥获取
		length = keyfile.readkey(num, pTemp32);
		keyID = pTemp32[3];
		algID = pTemp32[4];
		Util.arrayCopyNonAtomic(pTemp32, (short)5, pTemp16, (short)0, length);
		
		//产生随机数
		RandData.GenerateSecureRnd();
		RandData.getRndValue(pTemp32, (short)0);//产生随机数
		
		//返回响应数据
		Util.arrayCopyNonAtomic(EP_balance, (short)0, data, (short)0, (short)4);      //电子钱包余额
		Util.arrayCopyNonAtomic(EP_offline, (short)0, data,  (short)4, (short)2);      //电子钱包脱机交易序号
		byte[] touzhi = {0x00,0x00,0x00};
		Util.arrayCopyNonAtomic(touzhi, (short)0, data,  (short)6, (short)3);      	  //透支限额
		data[9] = keyID;                                                              //密钥版本号
		data[10] = algID;                                                              //算法标识
		RandData.getRndValue(data, (short)11);                                         //随机数
		
		return 0;
		
	}
	/*
	 * 功能：消费命令的实现
	 * 参数：data 命令报文中的数据段
	 * 返回：0 命令执行成功； 1 MAC校验错误 2 消费超额； 3 密钥未找到
	 */
	public final short purchase(byte[] data){
		short rc;

		
		//产生过程密钥
		Util.arrayCopyNonAtomic(EP_offline, (short)0, pTemp32, (short)4, (short)2);		//脱机交易序列号EP_offline
		Util.arrayCopyNonAtomic(data, (short)2, pTemp32, (short)6, (short)2);			//终端交易序号的最后两个字节
		
		EnCipher.gen_SESPK(pTemp16, pTemp32, (short)0, (short)8, pTemp82, (short)0); 	//过程密钥
		
		//产生MAC1
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);   		//交易金额
		pTemp32[4] = (byte)0x06;                                                      	//交易类型标识
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);        //终端机编号
		Util.arrayCopyNonAtomic(data, (short)4, pTemp32, (short)11, (short)7);			//交易日期和时间
		
		
		EnCipher.gmac4(pTemp82, pTemp32, (short)18, pTemp41);							//产生mac1
		
		//检验MAC1
		if(Util.arrayCompare(data, (short)11, pTemp41, (short)0, (short)4) != (byte)0x00)
			return (short)1;	
			
		
		//脱机交易序号加1
		rc = Util.makeShort(EP_offline[0], EP_offline[1]);
		rc ++;
		if(rc > (short)256)
			rc = (short)1;
		Util.setShort(EP_offline, (short)0, rc);
		
		//电子钱包金额减少
		rc = decrease(pTemp42, true);
		if(rc != (short)0)
			return (short)2;
	
		//MAC2生成
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       	//交易金额
		EnCipher.gmac4(pTemp82, pTemp32, (short)4, pTemp41);
		
		
		//TAC数据
		Util.arrayCopyNonAtomic(pTemp42, (short)0, pTemp32, (short)0, (short)4);       	//交易金额
		pTemp32[4] = (byte)0x06;                                                       	//交易类型标识
		Util.arrayCopyNonAtomic(pTemp81, (short)0, pTemp32, (short)5, (short)6);     	//终端机编号
		Util.arrayCopyNonAtomic(data, (short)0, pTemp32, (short)11, (short)4);     		//终端交易序号
		Util.arrayCopyNonAtomic(data, (short)4, pTemp32, (short)15, (short)7);//交易日期与时间
		
		//TAC的计算
		short length, num;
		num = keyfile.findKeyByType((byte)0x34);
		length = keyfile.readkey(num, pTemp16);
		
		if(length == 0)
			return (short)3;
		Util.arrayCopyNonAtomic(pTemp16, (short)5, pTemp82, (short)0, (short)8);
		EnCipher.xorblock8(pTemp82, pTemp16, (short)13);//密钥左8位和右8位异或得到新密钥
		
		//得到tac同时返回tac给终端
		byte[] temp = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(pTemp16, (short)13, temp, (short)0, (short)8);
		
		
		//返回mac2
		Util.arrayCopyNonAtomic(pTemp41, (short)0, data, (short)4, (short)4);
		
		EnCipher.gmac4(temp, pTemp32, (short)22, data);
		
		return 0;
	}
	/*
	 * 功能：电子钱包余额获取
	 * 参数：data 电子钱包余额的缓冲区
	 * 返回： 0
	 */
	public final short get_balance(byte[] data){
		for(short i = 0;i < 4;i++)
		{
			data[i] = EP_balance[i];
		}
		return 0;
	}
}
