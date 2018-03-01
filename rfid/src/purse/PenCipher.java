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
	 * ���ܣ�DES��������
	 * ������key ��Կ; kOff ��Կ��ƫ����; data ��Ҫ���мӽ��ܵ�����; 
	 * dOff ����ƫ������ dLen ���ݵĳ���; r �ӽ��ܺ�����ݻ�������
	 *  rOff �������ƫ������ mode ���ܻ��������ģʽ:Cipher.MODE_DECRYPT/Cipher.MODE_ENCRYPT
	 * ���أ���
	 */
	public final void cdes(byte[] akey, short kOff, byte[] data, short dOff, short dLen, byte[] r, short rOff, byte mode){
		//���ãģţ���Կ
		((DESKey)deskey).setKey(akey, kOff);
		//��ʼ����Կ������ģʽ
		desEngine.init(deskey, mode);
		//����
		desEngine.doFinal(data, dOff, dLen, r, rOff);
	}
	
	/*
	 * ���ܣ����ɹ�����Կ
	 * ������key ��Կ�� data ��Ҫ���ܵ����ݣ� dOff �����ܵ�����ƫ������ dLen �����ܵ����ݳ��ȣ� r ���ܺ�����ݣ� rOff ���ܺ�����ݴ洢ƫ����
	 * ���أ���
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
	 * ���ܣ�8���ֽڵ�������
	 * ������d1 ����������������1 d2:����������������2 d2_off:����2��ƫ����
	 * ���أ���
	 */
	public final void xorblock8(byte[] d1, byte[] d2, short d2_off){
		
		//�������ݿ�������������������ݿ�d2��
		short i = 0;
		while(i < 8)				
		{
			d2[d2_off] ^= d1[i];
			d2_off++;
			i++;
		}
	}
	
	/*
	 * ���ܣ��ֽ����
	 * ������data ��Ҫ�������ݣ� len ���ݵĳ���
	 * ���أ�������ֽڳ���
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
	 * ���ܣ�MAC��TAC������
	 * ������key ��Կ; data ��Ҫ���ܵ�����; dl ��Ҫ���ܵ����ݳ��ȣ� mac ������õ���MAC��TAC��
	 * ���أ���
	 */
	public final void gmac4(byte[] key, byte[] data, short dl, byte[] mac){
		//todo
		//����䣬�ٽ��ж���des
		short new_dl = pbocpadding(data,dl);
		byte[] ini_num = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		short num = (short)(new_dl / 8); //�зֳɶ��ٿ�
		
		/*�޸����ǰ�汾Ϊ:xorblock8(data, ini_num, (short)0);*/
		xorblock8(ini_num, data, (short)0);
		
		byte[] cipher = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);//�����ݴ�
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