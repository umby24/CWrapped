using System;
using System.IO.Compression;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace CWrapped
{
    public class Wrapped : IDisposable
    {
        // -- Credits to SirCmpwn for encryption support, as taken from SMProxy.
        public NetworkStream Stream;
        public AesStream Crypto;
        public bool CompEnabled = false;
        public int CompThreshold;
        public bool EncEnabled = false;
        public byte[] Buffer;
         
        public Wrapped(NetworkStream stream) {
            Stream = stream;
        }

        public void InitEncryption(byte[] key) {
            Crypto = new AesStream(Stream, key);
        }

        public void SetCompression(int threshold) {
            if (threshold == -1) {
                CompEnabled = false;
                CompThreshold = 0;
            }

            CompEnabled = true;
            CompThreshold = threshold;
        }


        // -- Strings

        public string ReadString() {
            var length = ReadVarInt();
            var stringBytes = ReadByteArray(length);

            return Encoding.UTF8.GetString(stringBytes);
        }

        public void WriteString(string message) {
            var length = GetVarIntBytes(message.Length);
            var final = new byte[message.Length + length.Length];

            System.Buffer.BlockCopy(length, 0, final, 0, length.Length);
            System.Buffer.BlockCopy(Encoding.UTF8.GetBytes(message), 0, final, length.Length, message.Length);

            Send(final);
        }

        // -- Shorts

        public short ReadShort() {
            var bytes = ReadByteArray(2);
            Array.Reverse(bytes);

            return BitConverter.ToInt16(bytes, 0);
        }

        public void WriteShort(short message) {
            var bytes = BitConverter.GetBytes(message);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Integer

        public int ReadInt() {
            var bytes = ReadByteArray(4);
            Array.Reverse(bytes);

            return BitConverter.ToInt32(bytes, 0);
        }

        public void WriteInt(int number) {
            var bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- VarInt

        public int ReadVarInt() {
            var result = 0;
            var length = 0;

            while (true) {
                var current = ReadByte();
                result |= (current & 0x7F) << length++ * 7;

                if (length > 5)
                    throw new InvalidDataException("Invalid varint: Too long.");

                if ((current & 0x80) != 0x80)
                    break;
            }

            return result;
        }

        public void WriteVarInt(long number) {
            Send(GetVarIntBytes(number));
        }

        public byte[] GetVarIntBytes(long number) {
            var byteBuffer = new byte[10];
            short pos = 0;

            do {
                var byteVal = (byte)(number & 0x7F);
                number >>= 7;

                if (number != 0)
                    byteVal |= 0x80;

                byteBuffer[pos] = byteVal;
                pos += 1;
            } while (number != 0);

            var result = new byte[pos];
            System.Buffer.BlockCopy(byteBuffer, 0, result, 0, pos);

            return result;
        }

        // -- Long

        public long ReadLong() {
            var bytes = ReadByteArray(8);
            Array.Reverse(bytes);

            return BitConverter.ToInt64(bytes, 0);
        }

        public void WriteLong(long number) {
            var bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Doubles

        public double ReadDouble() {
            var bytes = ReadByteArray(8);
            Array.Reverse(bytes);

            return BitConverter.ToDouble(bytes, 0);
        }

        public void WriteDouble(double number) {
            var bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Floats

        public float ReadFloat() {
            var bytes = ReadByteArray(4);
            Array.Reverse(bytes);

            return BitConverter.ToSingle(bytes, 0);
        }

        public void WriteFloat(float number) {
            var bytes = BitConverter.GetBytes(number);
            Array.Reverse(bytes);

            Send(bytes);
        }

        // -- Bytes

        public byte ReadByte() {
            return ReadSingleByte();
        }

        public void WriteByte(byte mybyte) {
            try {
                SendByte(mybyte);
            } catch {
            }
        }

        // -- SByte

        public sbyte ReadSByte() {
            try {
                return unchecked((sbyte)ReadSingleByte());
            } catch {
                return 0;
            }
        }

        public void WriteSByte(sbyte mybyte) {
            try {
                SendByte(unchecked((byte)mybyte));
            } catch {
            }
        }

        // -- Bool

        public bool ReadBool() {
            try {
                return Convert.ToBoolean(ReadSingleByte());
            } catch {
                return false;
            }
        }

        public void WriteBool(bool mybool) {
            try {
                SendByte(Convert.ToByte(mybool));
            } catch {
            }
        }

        #region Send and Receive
        public byte ReadSingleByte() {
            if (EncEnabled)
                return (byte)Crypto.decryptStream.ReadByte();

            return (byte)Stream.ReadByte();
        }

        public byte[] ReadByteArray(int size) {
            var received = 0;
            var myBytes = new byte[size];

            while (received != size) {
                size -= received;

                if (received != 0)
                    received -= 1;

                if (EncEnabled)
                    received = Crypto.decryptStream.Read(myBytes, received, size);
                else 
                    Stream.Read(myBytes, received, size);
            }

            return myBytes;
        }

        public void Send(byte[] bArray) {
            if (Buffer != null) {
                var tempLength = Buffer.Length + bArray.Length;
                var tempBuff = new byte[tempLength];

                System.Buffer.BlockCopy(Buffer, 0, tempBuff, 0, Buffer.Length);
                System.Buffer.BlockCopy(bArray, 0, tempBuff, Buffer.Length, bArray.Length);

                Buffer = tempBuff;
            } else {
                Buffer = bArray;
            }
        }

        void SendByte(byte thisByte) {
            if (Buffer != null) {
                var tempBuff = new byte[Buffer.Length + 1];

                System.Buffer.BlockCopy(Buffer, 0, tempBuff, 0, Buffer.Length);
                tempBuff[Buffer.Length] = thisByte;

                Buffer = tempBuff;
            } else {
                Buffer = new[] { thisByte };
            }
        }

        public void Purge() {
            if (CompEnabled)
                PurgeModernWithCompression();
            else
                PurgeWithoutCompression();
        }

        private void PurgeWithoutCompression() {
            var lenBytes = GetVarIntBytes(Buffer.Length);

            var tempBuff = new byte[Buffer.Length + lenBytes.Length];

            System.Buffer.BlockCopy(lenBytes, 0, tempBuff, 0, lenBytes.Length);
            System.Buffer.BlockCopy(Buffer, 0, tempBuff, lenBytes.Length, Buffer.Length);

            if (EncEnabled)
                Crypto.encryptStream.Write(tempBuff, 0, tempBuff.Length);
            else
                Stream.Write(tempBuff, 0, tempBuff.Length);

            Buffer = null;
        }

        private void PurgeModernWithCompression() {
            var dataLength = 0; // -- UncompressedData.Length
            var data = Buffer;

            var packetLength = Buffer.Length + GetVarIntBytes(Buffer.Length).Length;

            if (packetLength >= CompThreshold) // -- if Packet length > threshold, compress
            {
                using (var outputStream = new MemoryStream())
                using (var inputStream = new DeflateStream(outputStream, CompressionMode.Compress))
                {
                    inputStream.Write(Buffer, 0, Buffer.Length);
                    inputStream.Close();

                    data = outputStream.ToArray();
                }

                dataLength = data.Length;
                packetLength = dataLength + GetVarIntBytes(data.Length).Length; // -- Calculate new packet length
            }


            var packetLengthByteLength = GetVarIntBytes(packetLength);
            var dataLengthByteLength = GetVarIntBytes(dataLength);

            var tempBuf = new byte[data.Length + packetLengthByteLength.Length + dataLengthByteLength.Length];

            System.Buffer.BlockCopy(packetLengthByteLength, 0, tempBuf, 0, packetLengthByteLength.Length);
            System.Buffer.BlockCopy(dataLengthByteLength, 0, tempBuf, packetLengthByteLength.Length, dataLengthByteLength.Length);
            System.Buffer.BlockCopy(data, 0, tempBuf, packetLengthByteLength.Length + dataLengthByteLength.Length, data.Length);

            if (EncEnabled)
                Crypto.encryptStream.Write(tempBuf, 0, tempBuf.Length);
            else
                Stream.Write(tempBuf, 0, tempBuf.Length);

            Buffer = null;
        }

        #endregion
        
        public void Dispose() {
            if (Stream != null)
                Stream.Dispose();

            if (Crypto != null)
                Crypto.Dispose();
        }
    }
}
