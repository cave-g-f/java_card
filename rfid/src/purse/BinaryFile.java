package purse;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class BinaryFile {
	private short size;         //����Ͷ�ļ��Ĵ�С
	private byte[] binary;      //�������ļ�
	
	public BinaryFile(byte[] pdata){
		size = Util.makeShort(pdata[1], pdata[2]);
		binary = new byte[size];
	}
	
	/*
	 * ���ܣ�д�������
	 * ������off д��������ļ� ��ƫ������ dl  д������ݳ��ȣ� data д�������
	 * ���أ���
	 */
	public final void write_bineary(short off, short dl, byte[] data){
		Util.arrayCopyNonAtomic(data, (short)0, binary, off, dl);
	}
	/*
	 * ���ܣ����������ļ�
	 * ������off �����ƶ�ȡ��ƫ������len ��ȡ�ĳ��ȣ� data ���������ݵĻ�����
	 * ���أ����������ݵ��ֽڳ���
	 */
	public final short read_binary(short off, short len, byte[] data){
		Util.arrayCopyNonAtomic(binary, off, data, (short)0, len);
		
		return len;
	}
	/*
	 * ���ܣ���ȡ�������ļ���С
	 * ��������
	 * ���أ��������ļ��Ĵ�С
	 */
	public final short get_size(){
		return size;
	}
}
