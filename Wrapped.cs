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
        private readonly NetworkStream _stream;
        private AesStream _crypto;
        private bool _compression;
        public bool Encryption = false;
        private int _threshold;

        private byte[] _sendBuffer;
         
        public Wrapped(NetworkStream stream) {
            _stream = stream;
        }

        public void InitEncryption(byte[] key) {
            _crypto = new AesStream(_stream, key);
        }

        public void SetCompression(int threshold) {
            if (threshold == -1) {
                _compression = false;
                _threshold = 0;
            }

            _compression = true;
            _threshold = threshold;
        }

        public void Dispose() {
            if (_stream != null)
                _stream.Dispose();

            if (_crypto != null)
                _crypto.Dispose();
        }

        // -- Strings

        public string ReadString() {
            var length = ReadVarInt();
            var stringBytes = ReadByteArray(length);

            return Encoding.UTF8.GetString(stringBytes);
        }

        public void WriteString(string message) {
            var length = GetVarintBytes(message.Length);
            var final = new byte[message.Length + length.Length];

            Buffer.BlockCopy(length, 0, final, 0, length.Length);
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(message), 0, final, length.Length, message.Length);

            AddBytes(final);
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

            AddBytes(bytes);
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

            AddBytes(bytes);
        }

        // -- VarInt

        public int ReadVarInt() {
            var result = 0u;
            var length = 0;

            while (true) {
                var current = ReadSingleByte();
                result |= (current & 0x7Fu) << length++ * 7;

                if (length > 5)
                    throw new Exception("VarInt Too long");

                if ((current & 0x80) != 128)
                    break;
            }

            return (int)result;
        }

        public long ReadVarLong() {
            ulong result = 0;
            var length = 0;

            while (true) {
                var current = ReadSingleByte();
                result |= (current & 0x7Fu) << length++ * 7;

                if (length > 7)
                    throw new Exception("VarLong Too long");

                if ((current & 0x80) != 128)
                    break;
            }

            return (long)result;
        }

        public void WriteVarInt(int value) {
            AddBytes(GetVarintBytes(value));
        }

        public void WriteVarLong(long value) {
            AddBytes(GetVarLongBytes(value));
        }

        public byte[] GetVarintBytes(int value) {
            var byteBuffer = new byte[10];
            short pos = 0;

            do {
                var byteVal = (byte)(value & 0x7F);
                value >>= 7;

                if (value != 0)
                    byteVal |= 0x80;

                byteBuffer[pos] = byteVal;
                pos += 1;
            } while (value != 0);

            var result = new byte[pos];
            Buffer.BlockCopy(byteBuffer, 0, result, 0, pos);

            return result;
        }

        public byte[] GetVarLongBytes(long value) {
            var byteBuffer = new byte[10];
            short pos = 0;

            do {
                var byteVal = (byte)(value & 0x7F);
                value >>= 7;

                if (value != 0)
                    byteVal |= 0x80;

                byteBuffer[pos] = byteVal;
                pos += 1;
            } while (value != 0);

            var result = new byte[pos];
            Buffer.BlockCopy(byteBuffer, 0, result, 0, pos);

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

            AddBytes(bytes);
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

            AddBytes(bytes);
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

            AddBytes(bytes);
        }

        // -- Bytes

        public byte ReadByte() {
            return ReadSingleByte();
        }

        public void WriteByte(byte mybyte) {
            try {
                AddSingleByte(mybyte);
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
                AddSingleByte(unchecked((byte)mybyte));
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
                AddSingleByte(Convert.ToByte(mybool));
            } catch {
            }
        }

        #region AddBytes and Receive
        public byte ReadSingleByte() {
            if (Encryption)
                return (byte)_crypto.DecryptStream.ReadByte();

            return (byte)_stream.ReadByte();
        }

        public byte[] ReadByteArray(int size) {
            var received = 0;
            var myBytes = new byte[size];

            while (received != size) {
                size -= received;

                if (received != 0)
                    received -= 1;

                if (Encryption)
                    received = _crypto.DecryptStream.Read(myBytes, received, size);
                else 
                    _stream.Read(myBytes, received, size);
            }

            return myBytes;
        }

        public void AddBytes(byte[] bArray) {
            if (_sendBuffer != null) {
                var tempLength = _sendBuffer.Length + bArray.Length;
                var tempBuff = new byte[tempLength];

                Buffer.BlockCopy(_sendBuffer, 0, tempBuff, 0, _sendBuffer.Length);
                Buffer.BlockCopy(bArray, 0, tempBuff, _sendBuffer.Length, bArray.Length);

                _sendBuffer = tempBuff;
            } else 
                _sendBuffer = bArray;
            
        }

        public void AddSingleByte(byte thisByte) {
            if (_sendBuffer != null) {
                var tempBuff = new byte[_sendBuffer.Length + 1];

                Buffer.BlockCopy(_sendBuffer, 0, tempBuff, 0, _sendBuffer.Length);
                tempBuff[_sendBuffer.Length] = thisByte;

                _sendBuffer = tempBuff;
            } else 
                _sendBuffer = new[] { thisByte };
            
        }

        public void Purge() {
            var dataLength = _sendBuffer.Length;
            var lengthBytes = GetVarintBytes(dataLength);
            byte[] tempBuff;

            if (!_compression) {
                // -- Format: [VarInt Packet Length] [Packet ID] [ Packet Data]
                tempBuff = new byte[lengthBytes.Length + dataLength];
                Buffer.BlockCopy(lengthBytes, 0, tempBuff, 0, lengthBytes.Length);
                Buffer.BlockCopy(_sendBuffer, 0, tempBuff, lengthBytes.Length, dataLength);
            } else {
                // -- Format: [VarInt Packet Length] [VarInt: 0 if uncompressed, otherwise length of compressed data] [ Packet ID ] [ Packet Data ]
                if (_sendBuffer.Length <= _threshold) {
                    // -- Compression Triggered.
                    using (var outStream = new MemoryStream()) {
                        using (var compressStream = new DeflateStream(outStream, CompressionMode.Compress)) {
                            compressStream.Write(_sendBuffer, 0, dataLength);
                        }
                        _sendBuffer = outStream.ToArray();
                    }
                } else {
                    dataLength = 0;
                    lengthBytes = GetVarintBytes(dataLength);
                }

                var totalLenBytes = GetVarintBytes(lengthBytes.Length + _sendBuffer.Length);
                tempBuff = new byte[lengthBytes.Length + _sendBuffer.Length + totalLenBytes.Length];
                Buffer.BlockCopy(totalLenBytes, 0, tempBuff, 0, totalLenBytes.Length);
                Buffer.BlockCopy(lengthBytes, 0, tempBuff, totalLenBytes.Length, lengthBytes.Length);
                Buffer.BlockCopy(_sendBuffer, 0, tempBuff, totalLenBytes.Length + lengthBytes.Length, _sendBuffer.Length);
            }

            if (Encryption)
                _crypto.EncryptStream.Write(tempBuff, 0, tempBuff.Length);
            else
                _stream.Write(tempBuff, 0, tempBuff.Length);

            _sendBuffer = null;
        }
        #endregion
        

    }
}
