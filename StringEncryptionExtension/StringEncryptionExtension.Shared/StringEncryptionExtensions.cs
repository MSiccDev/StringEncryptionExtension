using System;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace StringEncryptionExtension
{
    public static class StringEncryptionExtensions
    {

        static StringEncryptionExtensions()
        {
        }

        /// <summary>
        /// Method to obtain a pre shared key
        /// </summary>
        /// <returns>pre shared key string representation</returns>
        private static string GetPreSharedKey()
        {
            //todo: implement your logic for a pre shared key here
            return null;
        }

        /// <summary>
        /// encrypts a string
        /// </summary>
        /// <param name="text">string to encrypt</param>
        /// <param name="psk">pre shared key used to encrypt</param>
        /// <returns></returns>
        public static string EncryptString(this string text, string psk = null)
        {
            //if no PSK is provided, load it from the PreSharedKey method. 
            //remember to save this key securely between your apps or provide a key that is unique but available to both platforms!
            if (string.IsNullOrEmpty(psk))
            {
                if (string.IsNullOrEmpty(GetPreSharedKey()))
                {
                    throw new NullReferenceException("Encryption is only secure with a pre shared key. Please make sure PreSharedKey() returns a valid string.");
                }
                else
                {
                    psk = GetPreSharedKey();
                }
            }

            //load the key and hash alghorithm providers
            var symmetricKeyProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            var hashAlghorithmProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);
            //create a new hash object
            CryptographicHash AEShash = hashAlghorithmProvider.CreateHash();

            string encryptedString = "";

            //try catch because of the chance of a too short PSK
            try
            {
                //getting psk as byte array
                byte[] pSkBytes = Encoding.UTF8.GetBytes(psk);
                //declare a new hash byte array
                byte[] hash = new byte[32];

                //[] key must have a length of 32 bytes
                //if pskBytes is long enough, use it
                if (pSkBytes.Length >= 32)
                {
                    Array.Copy(pSkBytes, 0, hash, 0, 32);
                }
                //if pskbytes is too short, append it two times together 
                //the CryptographicBuffer.CreateFromByteArray() method creates a 16 byte array even if you provide only a single letter/number as pre shared key
                else
                {
                    AEShash.Append(CryptographicBuffer.CreateFromByteArray(Encoding.UTF8.GetBytes(psk)));

                    byte[] temp;
                    CryptographicBuffer.CopyToByteArray(AEShash.GetValueAndReset(), out temp);

                    Array.Copy(temp, 0, hash, 0, 16);
                    Array.Copy(temp, 0, hash, 15, 16);
                }

                //create the symmetric key that is used to encrypt the string from the hash bytes array
                var AESkey = symmetricKeyProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(hash));

                //create the IBuffer that is for the string
                IBuffer buffer = CryptographicBuffer.CreateFromByteArray(Encoding.UTF8.GetBytes(text));

                //encrypt the byte array with the symmetric key
                encryptedString = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(AESkey, buffer, null));

                //return the Base64 string representation of the encrypted string byte array
                return encryptedString;
            }
            catch (Exception ex)
            {
                return null;
            }

        }


        /// <summary>
        /// decyrpts an encrypted base64 string
        /// </summary>
        /// <param name="text">base64 string to decrypt</param>
        /// <param name="psk">pre shared key used to decrypt</param>
        /// <returns></returns>
        public static string DecryptString(this string text, string psk = null)
        {
            //if no PSK is provided, load it from the PreSharedKey method. 
            //remember to save this key securely between your apps or provide a key that is unique but available to both platforms!
            if (string.IsNullOrEmpty(psk))
            {
                if (string.IsNullOrEmpty(GetPreSharedKey()))
                {
                    throw new NullReferenceException("Encryption is only secure with a pre shared key. Please make sure PreSharedKey() returns a valid string.");
                }
                else
                {
                    psk = GetPreSharedKey();
                }
            }

            //load the key and hash alghorithm providers
            var symmetricKeyProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            var hashAlghorithmProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);
            //create a new hash object
            CryptographicHash AEShash = hashAlghorithmProvider.CreateHash();

            string decryptedString = "";

            //try catch because of the chance of a too short PSK
            try
            {
                //getting psk as byte array
                byte[] pSkBytes = Encoding.UTF8.GetBytes(psk);
                //declare a new hash byte array
                byte[] hash = new byte[32];

                //[] key must have a length of 32 bytes
                //if pskBytes is long enough, use it
                if (pSkBytes.Length >= 32)
                {
                    Array.Copy(pSkBytes, 0, hash, 0, 32);
                }
                //if pskbytes is too short, append it two times together 
                //the CryptographicBuffer.CreateFromByteArray() method creates a 16 byte array even if you provide only a single letter/number as pre shared key
                else
                {
                    AEShash.Append(CryptographicBuffer.CreateFromByteArray(Encoding.UTF8.GetBytes(psk)));

                    byte[] temp;
                    CryptographicBuffer.CopyToByteArray(AEShash.GetValueAndReset(), out temp);

                    Array.Copy(temp, 0, hash, 0, 16);
                    Array.Copy(temp, 0, hash, 15, 16);
                }

                //create the symmetric key that is used to encrypt the string from the hash bytes array
                var AESkey = symmetricKeyProvider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(hash));

                //decode the input Base64 string
                IBuffer buffer = CryptographicBuffer.DecodeFromBase64String(text);
                //declare new byte array
                byte[] dectryptedBytes;
                //decrypt the IBuffer back to byte array
                CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(AESkey, buffer, null), out dectryptedBytes);
                //get string back from the byte array
                decryptedString = Encoding.UTF8.GetString(dectryptedBytes, 0, dectryptedBytes.Length);

                //return plain text
                return decryptedString;
            }
            catch (Exception ex)
            {
                return null;
            }

        }

    }

}
