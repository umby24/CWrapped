using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;

namespace CWrapped
{
    public class Wrapped
    {
        // -- Credits to SirCmpwn for encryption support, as taken from SMProxy.
        public NetworkStream _stream;
        public AesStream crypto;
        public bool EncEnabled = false;
        public byte[] buffer;

        public Wrapped(NetworkStream stream) {
            _stream = stream;
        }

        public void InitEncryption(byte[] key) {
            crypto = new AesStream(_stream, key);
        }

        // -- Strings

        public string readString() {
            int length = readVarInt();
            byte[] stringBytes = readByteArray(length);

            return Encoding.UTF8.GetString(stringBytes);
        }

        public void writeString(string message) {
            byte[] length = getVarIntBytes((long)message.Length);
            byte[] final = new byte[message.Length + length.Length];

            Buffer.BlockCopy(length, 0, final, 0, length.Length);
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(message), 0, final, length.Length, message.Length);

            Send(final);
        }

        // -- Shorts

        public short readShort() {
            byte[] bytes = readByteArray(2);
            Array.Reverse(bytes);

            return BitConverter.ToInt16(bytes, 0);
        }

        public void writeShort(short message) {
            byte[] bytes = BitConverter.GetBytes(message);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Integer

        public int readInt() {
            byte[] bytes = readByteArray(4);
            Array.Reverse(bytes);

            return BitConverter.ToInt32(bytes, 0);
        }

        public void writeInt(int number) {
            byte[] bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- VarInt

        public int readVarInt() {
            int result = 0;
            int length = 0;

            while (true) {
                byte current = readByte();
                result |= (current & 0x7F) << length++ * 7;

                if (length > 5)
                    throw new InvalidDataException("Invalid varint: Too long.");

                if ((current & 0x80) != 0x80)
                    break;
            }

            return result;
        }

        public void writeVarInt(long number) {
            Send(getVarIntBytes(number));
        }

        public byte[] getVarIntBytes(long number) {
            byte[] byteBuffer = new byte[10];
            short pos = 0;

            do {
                byte byteVal = (byte)(number & 0x7F);
                number >>= 7;

                if (number != 0)
                    byteVal |= 0x80;

                byteBuffer[pos] = byteVal;
                pos += 1;
            } while (number != 0);

            byte[] result = new byte[pos];
            Buffer.BlockCopy(byteBuffer, 0, result, 0, pos);

            return result;
        }

        // -- Long

        public long readLong() {
            byte[] bytes = readByteArray(8);
            Array.Reverse(bytes);

            return BitConverter.ToInt64(bytes, 0);
        }

        public void writeLong(long number) {
            byte[] bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Doubles

        public double readDouble() {
            byte[] bytes = readByteArray(8);
            Array.Reverse(bytes);

            return BitConverter.ToDouble(bytes, 0);
        }

        public void writeDouble(double number) {
            byte[] bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Floats

        public float readFloat() {
            byte[] bytes = readByteArray(4);
            Array.Reverse(bytes);

            return BitConverter.ToSingle(bytes, 0);
        }

        public void writeFloat(float number) {
            byte[] bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Bytes

        public byte readByte() {
            return readSingleByte();
        }

        public void writeByte(byte mybyte) {
            try {
                SendByte(mybyte);
            } catch {
                return;
            }
        }

        // -- SByte

        public sbyte readSByte() {
            try {
                return Convert.ToSByte(readSingleByte());
            } catch {
                return 0;
            }
        }

        public void writeSByte(sbyte mybyte) {
            try {
                SendByte(Convert.ToByte(mybyte));
            } catch {
                return;
            }
        }

        // -- Bool

        public bool readBool() {
            try {
                return Convert.ToBoolean(readSingleByte());
            } catch {
                return false;
            }
        }

        public void writeBool(bool mybool) {
            try {
                SendByte(Convert.ToByte(mybool));
            } catch {
                return;
            }
        }

        #region Send and Receive
        public byte readSingleByte() {
            if (EncEnabled)
                return (byte)crypto.decryptStream.ReadByte();
            else
                return (byte)_stream.ReadByte();
        }

        public byte[] readByteArray(int size) {
            if (!EncEnabled) {
                byte[] myBytes = new byte[size];
                int BytesRead;

                BytesRead = _stream.Read(myBytes, 0, size);

                while (true) {
                    if (BytesRead != size) {
                        int newSize = size - BytesRead;
                        int BytesRead1 = _stream.Read(myBytes, BytesRead - 1, newSize);

                        if (!(BytesRead1 == newSize)) {
                            size = newSize;
                            BytesRead = BytesRead1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                return myBytes;
            } else {
                byte[] myBytes = new byte[size];
                int BytesRead;

                BytesRead = crypto.decryptStream.Read(myBytes, 0, size);

                while (true) {
                    if (BytesRead != size) {
                        int newSize = size - BytesRead;
                        int BytesRead1 = crypto.decryptStream.Read(myBytes, BytesRead - 1, newSize);

                        if (!(BytesRead1 == newSize)) {
                            size = newSize;
                            BytesRead = BytesRead1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                return myBytes;
            }
        }

        public void Send(byte[] bArray) {
            if (buffer != null) {
                int tempLength = buffer.Length + bArray.Length;
                byte[] tempBuff = new byte[tempLength];

                Buffer.BlockCopy(buffer, 0, tempBuff, 0, buffer.Length);
                Buffer.BlockCopy(bArray, 0, tempBuff, buffer.Length, bArray.Length);

                buffer = tempBuff;
            } else {
                buffer = bArray;
            }
        }

        void SendByte(byte thisByte) {
            if (buffer != null) {
                byte[] tempBuff = new byte[buffer.Length + 1];

                Buffer.BlockCopy(buffer, 0, tempBuff, 0, buffer.Length);
                tempBuff[buffer.Length] = thisByte;

                buffer = tempBuff;
            } else {
                buffer = new byte[] { thisByte };
            }
        }

        public void Purge() {
            var lenBytes = getVarIntBytes(buffer.Length);

            byte[] tempBuff = new byte[buffer.Length + lenBytes.Length];

            Buffer.BlockCopy(lenBytes, 0, tempBuff, 0, lenBytes.Length);
            Buffer.BlockCopy(buffer, 0, tempBuff, lenBytes.Length, buffer.Length);

            if (EncEnabled)
                crypto.encryptStream.Write(tempBuff, 0, tempBuff.Length);
            else
                _stream.Write(tempBuff, 0, tempBuff.Length);

            buffer = null;
        }
        #endregion
    }
}
