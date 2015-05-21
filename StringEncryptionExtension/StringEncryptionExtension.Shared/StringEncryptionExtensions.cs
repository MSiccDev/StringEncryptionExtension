using System;
using System.Collections.Generic;
using System.Text;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace StringEncryptionExtension
{
    public static class StringEncryptionExtensions
    {

        //using PasswordVault enables our app to securely save encryption keys between platforms as it is roaming between TRUSTED devices!
        //to learn more about trusted devices: http://windows.microsoft.com/en-us/windows-8/what-is-trusted-device
        private static PasswordVault _passwordVault;

        static StringEncryptionExtensions()
        {
            _passwordVault = new PasswordVault();
        }


        #region symmetric key encryption
        /// <summary>
        /// Method to obtain a pre shared key
        /// </summary>
        /// <param name="resource">the resource name which will be used to get the key back</param>
        /// <param name="username">the username from your app</param>
        /// <param name="key">your own pre shared key</param>
        /// <returns>pre shared key string representation</returns>
        public static string GetKeyMaterialString(string resource = null, string username = null)
        {
            string key = "";

            if (string.IsNullOrEmpty(resource) && string.IsNullOrEmpty(username))
            {
                //replace with your resource name if suitable
                resource = "symmetricKey";
                //replace with your user's name/identifier
                username = "sampleUserName";                                
            }            

            //using try catch as FindAllByResource will throw an exception anyways if the specified resource is not found
            try
            {
                //search for our saved symmetric key
                var findSymmetricKey = _passwordVault.FindAllByResource(resource);
                //calling RetrievePassword you MUST!
                findSymmetricKey[0].RetrievePassword();
                key = findSymmetricKey[0].Password;
            }
            catch (Exception)
            {
                //getting a true random key buffer with a length of 32 bytes
                IBuffer randomKeyBuffer = CryptographicBuffer.GenerateRandom(32);

                key = CryptographicBuffer.EncodeToBase64String(randomKeyBuffer); 

                _passwordVault.Add(new PasswordCredential(resource, username, key));
            }
            
            return key;
        }

        /// <summary>
        /// encrypts a string
        /// </summary>
        /// <param name="text">string to encrypt</param>
        /// <param name="psk">pre shared key used to encrypt</param>
        /// <returns></returns>
        public static string EncryptStringSymmetric(this string text)
        {
            string encryptedString = "";

            //try
            //{
                //load the alghorithm providers
                var symmetricKeyProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

                //create the symmetric key that is used to encrypt the string from random keystring
                var cryptoKey = symmetricKeyProvider.CreateSymmetricKey(CryptographicBuffer.DecodeFromBase64String(GetKeyMaterialString()));

                //create the IBuffer that is for the string
                IBuffer buffer = CryptographicBuffer.CreateFromByteArray(Encoding.UTF8.GetBytes(text));

                //encrypt the byte array with the symmetric key
                encryptedString = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(cryptoKey, buffer, null));

                //return the Base64 string representation of the encrypted string byte array
                return encryptedString;
            //}
            //catch (Exception)
            //{
            //    return null;
            //}

        }


        /// <summary>
        /// decyrpts an encrypted base64 string
        /// </summary>
        /// <param name="text">base64 string to decrypt</param>
        /// <param name="psk">pre shared key used to decrypt</param>
        /// <returns></returns>
        public static string DecryptStringSymmetric(this string text)
        {
            string decryptedString = "";

            //try catch because of the chance of a too short PSK
            try
            {
                //load the alghorithm providers
                var symmetricKeyProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

                //create the symmetric key that is used to encrypt the string from random keystring
                var cryptoKey = symmetricKeyProvider.CreateSymmetricKey(CryptographicBuffer.DecodeFromBase64String(GetKeyMaterialString()));

                //decode the input Base64 string
                IBuffer buffer = CryptographicBuffer.DecodeFromBase64String(text);
                //declare new byte array
                byte[] dectryptedBytes;
                //decrypt the IBuffer back to byte array
                CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(cryptoKey, buffer, null), out dectryptedBytes);
                //get string back from the byte array
                decryptedString = Encoding.UTF8.GetString(dectryptedBytes, 0, dectryptedBytes.Length);

                //return plain text
                return decryptedString;
            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion



        #region asymmetric key encryption


        /// <summary>
        /// Method to get a new asymmetric KeyPair
        /// </summary>
        /// <returns>Dictionary with a private and a public Key</returns>
        public static Dictionary<string, string> GetAsymmetricKeyPair(string username = null)
        {
            Dictionary<string, string> keyDictionary;
            const string privKey = "asymmetricPrivateKey";
            const string pubKey = "asymmetricPublicKey";

            if (string.IsNullOrEmpty(username))
            {
                //replace with your user's name/identifier 
                username = "sampleUserName";
            }

            //using try catch as FindAllByResource will throw an exception anyways if the specified resource is not found
            try
            {
                //search for our save asymmetric keys
                var findAsymmetricPrivateKey = _passwordVault.FindAllByResource(privKey);
                //calling RetrievePassword you MUST!
                findAsymmetricPrivateKey[0].RetrievePassword();
                var findAsymmetricPublicKey = _passwordVault.FindAllByResource(pubKey);
                //calling RetrievePassword you MUST!
                findAsymmetricPublicKey[0].RetrievePassword();

                //loading our keys into a new Dictionary
                keyDictionary = new Dictionary<string, string>()
                {
                    {privKey, findAsymmetricPrivateKey[0].Password},
                    {pubKey, findAsymmetricPublicKey[0].Password}
                };
            }
            catch (Exception)
            {
                //declaring the Key Algortihm Provider and creating the KeyPair
                var asymmetricKeyProvider =
                    AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                CryptographicKey cryptographicKeyPair = asymmetricKeyProvider.CreateKeyPair(512);

                //converting the KeyPair into IBuffers
                IBuffer privateKeyBuffer =
                    cryptographicKeyPair.Export(CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);
                IBuffer publicKeyBuffer =
                    cryptographicKeyPair.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey);

                //encoding the key IBuffers into Base64 Strings and adding them to a new Dictionary
                keyDictionary = new Dictionary<string, string>
                {
                    {privKey, CryptographicBuffer.EncodeToBase64String(privateKeyBuffer)},
                    {pubKey, CryptographicBuffer.EncodeToBase64String(publicKeyBuffer)}
                };

                //saving the newly generated keys in PasswordVault
                _passwordVault.Add(new PasswordCredential(privKey, username, keyDictionary[privKey]));
                _passwordVault.Add(new PasswordCredential(pubKey, username, keyDictionary[pubKey]));
            }

            //return new Dictionary
            return keyDictionary;
        }


        /// <summary>
        /// encrypts a string using asymmetric key encryption
        /// </summary>
        /// <param name="text">the string to encrypt</param>
        /// <param name="publicKey">the public key portion of the asymmetric key</param>
        /// <returns>a Base64 encoded and encrypted string</returns>
        public static string EncryptStringAsymmetric(this string text, string publicKey = null)
        {
            //making sure we are providing a public key
            if (string.IsNullOrEmpty(publicKey))
            {
                var keyPairs = GetAsymmetricKeyPair();
                publicKey = keyPairs["asymmetricPublicKey"];
            }

            try
            {
                //converting the public key into an IBuffer
                IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(publicKey);
                
                //load the public key and the algorithm provider
                var asymmetricAlgorithmProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                var cryptoKey = asymmetricAlgorithmProvider.ImportPublicKey(keyBuffer, CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey);

                //converting the string into an IBuffer
                IBuffer buffer = CryptographicBuffer.CreateFromByteArray(Encoding.UTF8.GetBytes(text));

                string encryptedString = "";

                //perform the encryption
                encryptedString = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(cryptoKey, buffer, null));

                //return the Base64 string representation of the encrypted string
                return encryptedString;
            }
            catch (Exception)
            {
                return null;
            }

        }


        /// <summary>
        /// decrypts an encrypted string 
        /// </summary>
        /// <param name="text">the string to decrypt</param>
        /// <param name="privateKey">the private key portion of the asymmetric key</param>
        /// <returns>plain decrypted string</returns>
        public static string DecryptStringAsymmetric(this string text, string privateKey = null)
        {
            //making sure we are providing a public key
            if (string.IsNullOrEmpty(privateKey))
            {
                    var keyPairs = GetAsymmetricKeyPair();
                privateKey = keyPairs["asymmetricPrivateKey"];

                
            }

            try
            {
                //converting the private key into an IBuffer
                IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(privateKey);

                //load the private key and the algorithm provider
                var asymmetricAlgorithmProvider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                var cryptoKey = asymmetricAlgorithmProvider.ImportKeyPair(keyBuffer, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);

                //converting the encrypted text into an IBuffer
                IBuffer buffer = CryptographicBuffer.DecodeFromBase64String(text);

                //cdecrypting the IBuffer and convert its content into a Byte array 
                byte[] decryptedBytes;
                CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(cryptoKey, buffer, null), out decryptedBytes);

                string decryptedString = "";

                //getting back the plain text 
                decryptedString = Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length);

                return decryptedString;
            }
            catch (Exception)
            {
                return null;
            }

        }

        #endregion
    }

}
