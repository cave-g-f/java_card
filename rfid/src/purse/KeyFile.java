package purse;

import javacard.framework.Util;

public class KeyFile {
	public short size;         //��¼�����洢����
	public short recNum;       //��ǰ���洢�ļ�¼����
	private Object[] Key;      //��Կ��¼
	
	public KeyFile(){
		size = 4;
		recNum = 0;
		Key = new Object[size];//ÿһλ��ʾһ����Կ,�ɿ�����һ����ά����
	}
	
	/*
	 * ���ܣ������Կ
	 * ������tag ��Կ��ʶ���� length ��ֵ�ĳ��ȣ�value ��ֵ��5���ֽڵ���Կͷ+16���ֽڵ���Կֵ��
	 * ���أ���
	 */
	public void addkey(byte tag, short length, byte[] value){
		byte[] pbuf;
		
		pbuf = new byte[23];
		Key[recNum] = pbuf;
		pbuf[0] = tag;
		pbuf[1] = (byte)length;
		Util.arrayCopyNonAtomic(value, (short)0, pbuf, (short)2, length);
		recNum ++;
	}
	
	/*
	 * ���ܣ�ͨ����Կ��ʶ����ȡ��Կ��¼��
	 * ������tag ��Կ��ʶ��
	 * ���أ���¼��
	 */
	public short findkey(byte Tag){
		byte[] pbuf;
		if(recNum == 0)
			return 0;
		
		for(short i = 0;i < recNum;i ++){
			pbuf = (byte[])Key[i];
			if(pbuf[0] == Tag)
				return (short)(i + 1);
		}
		return 0;
	}
	
	/*
	 * ���ܣ�ͨ����Կ���ͻ�ȡ��Կ��¼��
	 * ������type ��Կ����
	 * ���أ���¼��
	 */
	public short findKeyByType(byte Type){
		byte[] pbuf;
		if(recNum == 0)
			return 0;
		
		for(short i = 0;i < recNum;i ++){
			pbuf = (byte[])Key[i];
			if(pbuf[2] == Type)
				return (short)(i + 1);
		}
		return 0;
	}
	
	/*
	 * ���ܣ�ͨ����Կ��¼�Ŷ�ȡ��Կ
	 * ������num ��Կ��¼�� data ����ȡ������Կ������
	 * ���أ���Կ�ĳ���
	 */
	public short readkey(short num, byte[] data){
		byte[] pdata;
		pdata = (byte[])Key[num - 1];
		Util.arrayCopyNonAtomic(pdata, (short)2, data, (short)0, (short)(pdata[1]));
		return (short)(pdata[1] - 5);
	}
	
}
