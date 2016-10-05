using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenPgpLib;

namespace UnitTest
{
    [TestClass]
    public class UnitTest
    {
        [TestMethod]
        public void Encrypt ()
        {
            // Keys generated using https://pgpkeygen.com/
            string inputFileName     = "inputFile.txt";
            string outputFileName    = "encrypted.txt";
            string publicKeyFileName = "public_key.txt";

            OpenPgp.EncryptFile (inputFileName, outputFileName, publicKeyFileName, false, false);
        }

        [TestMethod]
        public void Decrypt ()
        {
            // Keys generated using https://pgpkeygen.com/
            string inputFileName  = "encrypted.txt";
            string outputFileName = "decrypted.txt";
            string privateKey     = "private_key.txt";
            string password       = "mypassphrase";

            OpenPgp.DecryptFile (inputFileName, outputFileName, privateKey, password);
        }
    }
}
