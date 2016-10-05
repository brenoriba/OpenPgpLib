using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace OpenPgpLib
{
    public class OpenPgp
    {
        #region Decrypt methods
        /// <summary>
        /// Decrypt file using OpenPGP encryption
        /// </summary>
        /// <param name="inputFileName">Input file to be encrypted</param>
        /// <param name="outputFileName">Decrypted output file</param>
        /// <param name="pvtKeyFileName">PGP private key</param>
        /// <param name="password">PGP key password</param>
        public static void DecryptFile (string inputFileName, string outputFileName, string pvtKeyFileName, string password)
		{
			using (Stream input = File.OpenRead (inputFileName), privateKey = File.OpenRead (pvtKeyFileName))
			{
                DecryptFile (input, privateKey, outputFileName, password.ToCharArray ());
			}
		}
        
        /// <summary>
        /// Decrypt file
        /// </summary>
        /// <param name="inputStream">Input file stream</param>
        /// <param name="privateKey">Private key stream</param>
        /// <param name="outputFile">Output file name</param>
        /// <param name="password">PGP key password</param>
		private static void DecryptFile (Stream inputStream, Stream	privateKey, string outputFile, char[] password)
		{
            inputStream = PgpUtilities.GetDecoderStream (inputStream);

            PgpObjectFactory     pgpFactory    = new PgpObjectFactory (inputStream);
            PgpEncryptedDataList encryptedData = null;
            PgpObject            pgpObj        = pgpFactory.NextPgpObject ();
                
            // The first object might be a PGP marker packet.                
            if (pgpObj is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgpObj;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject ();
            }
                
            // Find the secret key
            PgpPrivateKey             sKey   = null;
            PgpPublicKeyEncryptedData pbe    = null;
			PgpSecretKeyRingBundle    pgpSec = new PgpSecretKeyRingBundle (PgpUtilities.GetDecoderStream (privateKey));

			foreach (PgpPublicKeyEncryptedData pked in encryptedData.GetEncryptedDataObjects ())
            {
                sKey = FindSecretKey (pgpSec, pked.KeyId, password);
                if (sKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

			if (sKey == null)
            {
                throw new ArgumentException ("Secret key for message not found.");
            }

            Stream           clear     = pbe.GetDataStream (sKey);
            PgpObjectFactory plainFact = new PgpObjectFactory (clear);
            PgpObject        message   = plainFact.NextPgpObject ();

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData   = (PgpCompressedData)message;
                PgpObjectFactory  pgpFact = new PgpObjectFactory (cData.GetDataStream ());

                message = pgpFact.NextPgpObject ();
            }

            // Write decrypted file to disk
            if (message is PgpLiteralData)
            {
                PgpLiteralData ld   = (PgpLiteralData)message;
                Stream         fOut = File.Create (outputFile);
				Stream         unc  = ld.GetInputStream ();

				Streams.PipeAll (unc, fOut);
				fOut.Close ();
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException ("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException ("Message is not a simple encrypted file - type unknown.");
            }
        }

        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to keyID if it exists
        /// </summary>
        /// <param name="pgpSec">A secret key ring collection</param>
        /// <param name="keyID">keyID we want</param>
        /// <param name="password">Password passphrase to decrypt secret key with</param>
        /// <returns>Private key</returns>
        private static PgpPrivateKey FindSecretKey (PgpSecretKeyRingBundle pgpSec, long keyID, char[] password)
		{
			PgpSecretKey pgpSecKey = pgpSec.GetSecretKey (keyID);
			if (pgpSecKey == null)
			{
				return null;
			}
			return pgpSecKey.ExtractPrivateKey (password);
		}
        #endregion

        #region Encrypt methods
        /// <summary>
        /// Encrypt input file
        /// </summary>        
        /// <param name="inputFileName">Input file name</param>
        /// <param name="outputFileName">Output file name</param>
        /// <param name="publicKeyFileName">Public key file name</param>
        /// <param name="armor">Armored output</param>
        /// <param name="withIntegrityCheck">Integrity check flag</param>
        public static void EncryptFile (string inputFileName, string outputFileName, string	publicKeyFileName, bool armor, bool withIntegrityCheck)
		{
			PgpPublicKey encKey = ReadPublicKey (publicKeyFileName);
			using (Stream output = File.Create (outputFileName))
			{
				EncryptFile (output, inputFileName, encKey, armor, withIntegrityCheck);
			}
		}

        /// <summary>
        /// Encrypt input file
        /// </summary>
        /// <param name="outputStream">Output file stream</param>
        /// <param name="inputFileName">Input file name</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="armor">Armored output flag</param>
        /// <param name="withIntegrityCheck">Integrity check flag</param>
        private static void EncryptFile (Stream	outputStream, string inputFileName, PgpPublicKey publicKey, bool armor, bool withIntegrityCheck)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream (outputStream);
            }

            byte[] bytes = CompressFile (inputFileName, CompressionAlgorithmTag.Zip);

			PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator (SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom ());
			encGen.AddMethod (publicKey);

			Stream cOut = encGen.Open (outputStream, bytes.Length);
			cOut.Write (bytes, 0, bytes.Length);
			cOut.Close ();

			if (armor)
			{
				outputStream.Close ();
			}
        }

        /// <summary>
        /// Compress file
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="algorithm">Algorithm tag</param>
        /// <returns>Byte array</returns>
        private static byte[] CompressFile (string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream               bOut    = new MemoryStream ();
            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator (algorithm);

            PgpUtilities.WriteFileToLiteralData (comData.Open (bOut), PgpLiteralData.Binary, new FileInfo (fileName));
            comData.Close ();

            return bOut.ToArray ();
        }

        /// <summary>
        /// Read public key
        /// </summary>
        /// <param name="fileName">Public key file name</param>
        /// <returns>PGP public key</returns>
        private static PgpPublicKey ReadPublicKey (string fileName)
		{
			using (Stream keyIn = File.OpenRead (fileName))
			{
				return ReadPublicKey (keyIn);
			}
		}

        /// <summary>
        /// A simple routine that opens a key ring file and loads the first available key suitable for encryption
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <returns>PGP public key</returns>
        private static PgpPublicKey ReadPublicKey (Stream input)
		{
			PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle (PgpUtilities.GetDecoderStream (input));
			
			// We just loop through the collection till we find a key suitable for encryption, in the real
			// world you would probably want to be a bit smarter about this.			
			foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings ())
			{
				foreach (PgpPublicKey key in keyRing.GetPublicKeys ())
				{
					if (key.IsEncryptionKey)
					{
						return key;
					}
				}
			}
			throw new ArgumentException ("Can't find encryption key in key ring.");
        }
        #endregion
    }
}
