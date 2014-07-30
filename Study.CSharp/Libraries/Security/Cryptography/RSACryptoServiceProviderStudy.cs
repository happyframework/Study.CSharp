using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

using NUnit.Framework;

namespace Study.CSharp.Libraries.Security.Cryptography
{
    /// <summary>
    /// http://blog.csdn.net/lubiaopan/article/details/6233517
    /// </summary>
    [TestFixture]
    public sealed class RSACryptoServiceProviderStudy
    {
        [Test]
        public void GenerateKey_Study()
        {
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                File.WriteAllText(PrivateKeyPath(), rsa.ToXmlString(true));
                File.WriteAllText(PublicKeyPath(), rsa.ToXmlString(false));
            }
        }

        [Test]
        public void Encrypt_Study()
        {
            Console.WriteLine(Encrypt("hello"));
        }

        [Test]
        public void Encrypt_With_Java_Public_Key_Study()
        {
            Console.WriteLine(Encrypt(
                        "hello"
                        , @"quLQGPpb2bXAAHArdVZW6MwB4cfuAhmnqjlWQla37bhrw+omgn/v+OUyLX1ZKd9jq8djaETus6+t
iPsn+2WoS0PASkJP0TpainChSRM5n6SYW+11L8QWhRX8mmXpRNUOnM2Gg8rKPnpbsnunCRXnp/yk
4B/HhHgNml1TO9LbsuU="
                        , "AQAB"));
        }

        [Test]
        public void Decrypt_Study()
        {
            Console.WriteLine(Decrypt(Encrypt(new String('A', 500))));
        }

        private static string Encrypt(string plain, string modulus, string exponent)
        {
            var dwKeySize = 1024;

            using (var rsa = new RSACryptoServiceProvider(dwKeySize))
            {
                var para = new RSAParameters();
                para.Exponent = Convert.FromBase64String(exponent);
                para.Modulus = Convert.FromBase64String(modulus);
                rsa.ImportParameters(para);
                int keySize = dwKeySize / 8;
                byte[] bytes = Encoding.UTF8.GetBytes(plain);
                // The hash function in use by the .NET RSACryptoServiceProvider here 
                // is SHA1
                // int maxLength = ( keySize ) - 2 - 
                //              ( 2 * SHA1.Create().ComputeHash( rawBytes ).Length );
                int maxLength = keySize - 42;
                int dataLength = bytes.Length;
                int iterations = dataLength / maxLength;
                StringBuilder stringBuilder = new StringBuilder();
                for (int i = 0; i <= iterations; i++)
                {
                    byte[] tempBytes = new byte[
                            (dataLength - maxLength * i > maxLength) ? maxLength :
                                                          dataLength - maxLength * i];
                    Buffer.BlockCopy(bytes, maxLength * i, tempBytes, 0,
                                      tempBytes.Length);
                    byte[] encryptedBytes = rsa.Encrypt(tempBytes, false);
                    // Why convert to base 64?
                    // Because it is the largest power-of-two base printable using only 
                    // ASCII characters
                    stringBuilder.Append(Convert.ToBase64String(encryptedBytes));
                }

                return stringBuilder.ToString();
            }
        }

        private static string Encrypt(string plain)
        {
            var dwKeySize = 1024;

            using (var rsa = new RSACryptoServiceProvider(dwKeySize))
            {
                rsa.FromXmlString(File.ReadAllText(PublicKeyPath()));
                int keySize = dwKeySize / 8;
                byte[] bytes = Encoding.UTF8.GetBytes(plain);
                // The hash function in use by the .NET RSACryptoServiceProvider here 
                // is SHA1
                // int maxLength = ( keySize ) - 2 - 
                //              ( 2 * SHA1.Create().ComputeHash( rawBytes ).Length );
                int maxLength = keySize - 42;
                int dataLength = bytes.Length;
                int iterations = dataLength / maxLength;
                StringBuilder stringBuilder = new StringBuilder();
                for (int i = 0; i <= iterations; i++)
                {
                    byte[] tempBytes = new byte[
                            (dataLength - maxLength * i > maxLength) ? maxLength :
                                                          dataLength - maxLength * i];
                    Buffer.BlockCopy(bytes, maxLength * i, tempBytes, 0,
                                      tempBytes.Length);
                    byte[] encryptedBytes = rsa.Encrypt(tempBytes, false);
                    // Why convert to base 64?
                    // Because it is the largest power-of-two base printable using only 
                    // ASCII characters
                    stringBuilder.Append(Convert.ToBase64String(encryptedBytes));
                }

                return stringBuilder.ToString();
            }
        }

        private static string Decrypt(string encrypted)
        {
            var dwKeySize = 1024;

            using (var rsa = new RSACryptoServiceProvider(dwKeySize))
            {
                rsa.FromXmlString(File.ReadAllText(PrivateKeyPath()));
                int base64BlockSize = ((dwKeySize / 8) % 3 != 0) ?
                  (((dwKeySize / 8) / 3) * 4) + 4 : ((dwKeySize / 8) / 3) * 4;
                int iterations = encrypted.Length / base64BlockSize;
                var arrayList = new List<byte>();
                for (int i = 0; i < iterations; i++)
                {
                    byte[] encryptedBytes = Convert.FromBase64String(
                         encrypted.Substring(base64BlockSize * i, base64BlockSize));
                    arrayList.AddRange(rsa.Decrypt(encryptedBytes, false));
                }

                return Encoding.UTF8.GetString(arrayList.ToArray());
            }
        }

        private static string PublicKeyPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public.xml");
        }

        private static string PrivateKeyPath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "private.xml");
        }
    }
}
