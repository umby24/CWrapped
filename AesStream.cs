using System;
using System.IO;
using System.Security.Cryptography;

namespace CWrapped {
    public class AesStream : IDisposable {
        public CryptoStream DecryptStream;
        public CryptoStream EncryptStream;
        public Stream BaseStream;

        public AesStream(Stream stream, byte[] key) {
            BaseStream = stream;

            var raj = GenerateAES(key);
            var encTrans = raj.CreateEncryptor();
            var decTrans = raj.CreateDecryptor();

            EncryptStream = new CryptoStream(BaseStream, encTrans, CryptoStreamMode.Write);
            DecryptStream = new CryptoStream(BaseStream, decTrans, CryptoStreamMode.Read);
        }

        private Rijndael GenerateAES(byte[] key) {
            var cipher = new RijndaelManaged {
                Mode = CipherMode.CFB,
                Padding = PaddingMode.None,
                KeySize = 128,
                FeedbackSize = 8,
                Key = key,
                IV = key
            };


            return cipher;
        }
        
        public void Dispose() {
            if (DecryptStream != null)
                DecryptStream.Dispose();

            if (EncryptStream != null)
                EncryptStream.Dispose();

            if (BaseStream != null)
                BaseStream.Dispose();
        }
    }
}
