CWrapped
========

Wrapped socket library ported to C#

Wrapped is a wrapper around .NET's NetworkStream for easy sending and receiving of Modern Minecraft primitive data types.

This library handles the AES encryption used by Minecraft as well as the endianness of data, making your life even easier!


Usage
=====

**Create a wrapped socket**

    var BaseSock = new TcpClient();
    BaseSock.Connect("127.0.0.1",25565);
  
    var BaseStream = BaseSock.GetStream();
    var wSock = new Wrapped(BaseStream);

  
**Sending a packet**
Chat message used as an example

    wSock.writeVarInt(0x01);
    wSock.writeString("Hello world!");
    wSock.Purge();
  
**Enabling encryption**

    wSock.InitEncryption(SharedKey);
    wSock.EncEnabled = true;

