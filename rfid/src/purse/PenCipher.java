package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	}
	
	/*
	 * 功能：DES加密运算
	 * 参数：key 密钥; kOff 密钥的偏移量; data 所要进行加解密的数据; 
	 * dOff 数据偏移量； dLen 数据的长度; r 加解密后的数据缓冲区；
	 *  rOff 结果数据偏移量； mode 加密或解密运算模式:Cipher.MODE_DECRYPT/Cipher.MODE_ENCRYPT
	 * 返回：无
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//设置ＤＥＳ密钥
		((DESKey)deskey).setKey(akey, kOff);
		//初始化密钥及加密模式
		desEngine.init(deskey, mode);
		//加密
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * 功能：生成过程密钥
	 * 参数：key 密钥； data 所要加密的数据； dOff 所加密的数据偏移量； dLen 所加密的数据长度； r 加密后的数据； rOff 加密后的数据存储偏移量
	 * 返回：无
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] r, short rOff){
		//todo
		byte[] temp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		byte[] temp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		//3DES
		cdes(key,(short)0,data,(short)0,dLen,temp1,(short)0,Cipher.MODE_ENCRYPT);
		cdes(key,(short)8,temp1,(short)0,dLen,temp2,(short)0,Cipher.MODE_DECRYPT);
		cdes(key,(short)0,temp2,(short)0,dLen,r,rOff,Cipher.MODE_ENCRYPT);
	}
	
	/*
	 * 功能：8个字节的异或操作
	 * 参数：d1 进行异或操作的数据1 d2:进行异或操作的数据2 d2_off:数据2的偏移量
	 * 返回：无
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		
		//两个数据块进行异或，异或结果存入数据块d2中
		short i = 0;
		while(i < 8)				
		{
			d2[d2_off] ^= d1[i];
			d2_off++;
			i++;
		}
	}
	
	/*
	 * 功能：字节填充
	 * 参数：data 所要填充的数据； len 数据的长度
	 * 返回：填充后的字节长度
	 */
	public final short pbocpadding(byte[] data, short len){
		data[len] = (byte)0x80;
		len++;
		while(len % 8 != 0)
		{
			data[len] = (byte)0x00;
			len++;
		}
	
		return len;
	}
	
	/*
	 * 功能：MAC和TAC的生成
	 * 参数：key 密钥; data 所要加密的数据; dl 所要加密的数据长度； mac 所计算得到的MAC和TAC码
	 * 返回：无
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//先填充，再进行多轮des
		short new_dl = pbocpadding(data,dl);
		byte[] ini_num = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		short num = (short)(new_dl / 8); //切分成多少块
		
		/*修改异或前版本为:xorblock8(data, ini_num, (short)0);*/
		xorblock8(ini_num, data, (short)0);
		
		byte[] cipher = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);//密文暂存
		for(short i = 1; i <= num;i++)
		{
			cdes(key,(short)0,data,(short)(8*(i-1)),(short)8,cipher,(short)0,Cipher.MODE_ENCRYPT);
			if(i < num)
			{
				xorblock8(cipher, data, (short)(8*i));			
			}
		}
		//mac/tac
		for(short i = 0;i < 4;i++)
		{
			mac[i] = cipher[i];
		}
	}
}