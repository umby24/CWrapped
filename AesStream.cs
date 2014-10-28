using System;
using System.IO;
using System.Security.Cryptography;

namespace CWrapped {
    public class AesStream : IDisposable {
        public CryptoStream decryptStream;
        public CryptoStream encryptStream;
        private byte[] _key;
        public Stream baseStream;

        public AesStream(Stream stream, byte[] key) {
            baseStream = stream;
            _key = key;

            var raj = GenerateAES(key);
            var encTrans = raj.CreateEncryptor();
            var decTrans = raj.CreateDecryptor();

            encryptStream = new CryptoStream(baseStream, encTrans, CryptoStreamMode.Write);
            decryptStream = new CryptoStream(baseStream, decTrans, CryptoStreamMode.Read);
        }

        private Rijndael GenerateAES(byte[] key) {
            var Cipher = new RijndaelManaged();

            Cipher.Mode = CipherMode.CFB;
            Cipher.Padding = PaddingMode.None;
            Cipher.KeySize = 128;
            Cipher.FeedbackSize = 8;
            Cipher.Key = key;
            Cipher.IV = key;

            return Cipher;
        }
        
        public void Dispose() {
            if (decryptStream != null)
                decryptStream.Dispose();

            if (encryptStream != null)
                encryptStream.Dispose();

            if (baseStream != null)
                baseStream.Dispose();
        }
    }
}
