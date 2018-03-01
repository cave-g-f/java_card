package purse;

import javacard.framework.JCSystem;

public class Papdu {
	public byte cla, ins, p1, p2;
	public short lc, le;
	public byte[] pdata;
	
	public Papdu(){
		//apdu�����ݶβ�����󳤶�Ϊ255�ֽ�
		pdata = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
	}
	
	/*
	 * ���ܣ��ж�APDU�����ǰ�������
	 * ��������
	 * ���أ�APDU����������ݵ��ж�
	 */
	public boolean APDUContainData(){
		switch(ins){
		case condef.INS_CREATE_FILE:
		case condef.INS_LOAD:
		case condef.INS_NIIT_TRANS:
		case condef.INS_WRITE_KEY:
		case condef.INS_WRITE_BIN:
		case condef.INS_PURCHASE:
		
			return true;
		}
		return false;
	}
}
