# java_card
java智能卡Applet应用实现电子钱包功能

本目录包含了电子钱包应用个人化的源代码包，下面是对各个文件的简要说明：

1、BinaryFile.java
  
   二进制文件的实现源码，其中实现了二进制文件的写入过程


2、condef.java

   常数定义文件，主要定义了电子钱包应用所使用到的APDU命令的指令类别INS


3、EPFile.java

   电子钱包文件的实现源码，其中包含的内部数据元有EP余额、EP联机交易序号、EP脱机交易序号，


4、KeyFile.java
   
   密钥文件的实现源码，其中实现了密钥的写入与密钥的读取


5、Papdu.java

   APDU的实现源码，APDU中除了包含CLA、INS、P1、P2、LC（LE）等必要部分，还包含了255个字节的数据段部分。


6、PenCipher.java

   COS安全管理部分的实现源码，其中实现了DES加密运算功能


7、Purse.java

   COS的传输管理与应用管理部分的实现源码。在此部分中，卡片接收了APDU命令后，正确地对APDU命令进行判断和处理后，返回数据和状态码。


9、Randgenerator.java

   随机数的产生机制，可从中产生4个字节的随机数
