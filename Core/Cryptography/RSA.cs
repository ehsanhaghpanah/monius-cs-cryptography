/**
 * Copyright (C) moniüs, 2017.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace monius.Cryptography
{
	/// <summary>
	/// RSA
	/// </summary>
	internal sealed class RSA : Cryptographer
	{
		private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

		#region Text Cryptography

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text"></param>
		/// <param name="size">RSA Key Size</param>
		/// <param name="path">RSA Public Key Store Path</param>
		/// <returns>Base64 formatted of Encrypted Data</returns>
		public static string Encrypt(string text, int size, string path)
		{
			try
			{
				var data = Encoding.UTF8.GetBytes(text);
				var encb = Encrypt(data, size, path);
				var bs64 = Convert.ToBase64String(encb);
				return bs64;
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="bs64">Base64 formatted of Encrypted Data</param>
		/// <param name="size">RSA Key Size</param>
		/// <param name="path">RSA Private Key Store Path</param>
		/// <returns>Decrypted Data</returns>
		public static string Decrypt(string bs64, int size, string path)
		{
			try
			{
				var data = Convert.FromBase64String(bs64);
				var decb = Decrypt(data, size, path);
				var text = Encoding.UTF8.GetString(decb);
				return text;
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		#endregion

		#region Byte Cryptography

		/// <summary>
		/// 
		/// </summary>
		/// <param name="data"></param>
		/// <param name="size">RSA Key Size</param>
		/// <param name="path">RSA Public Key Store Path</param>
		/// <returns>Encrypted Data</returns>
		public static byte[] Encrypt(byte[] data, int size, string path)
		{
			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = size;

					//
					// reading public key form store
					using (var reader = new StreamReader(path))
					{
						rsa.FromXmlString(reader.ReadToEnd());
						reader.Close();
					}

					//
					// performing encryption
					var encb = rsa.Encrypt(data, false);
					return encb;
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="data">Base64 formatted of Encrypted Data</param>
		/// <param name="size">RSA Key Size</param>
		/// <param name="path">RSA Private Key Store Path</param>
		/// <returns>Decrypted Data</returns>
		public static byte[] Decrypt(byte[] data, int size, string path)
		{
			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = size;

					//
					// reading private key form store
					using (var reader = new StreamReader(path))
					{
						rsa.FromXmlString(reader.ReadToEnd());
						reader.Close();
					}

					//
					// performing decryption
					var decb = rsa.Decrypt(data, false);
					return decb;
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		#endregion

		#region Byte Cryptography

		/// <summary>
		/// 
		/// </summary>
		/// <param name="data"></param>
		/// <param name="pbKy">RSA Public Key in Xml Format</param>
		/// <returns>Encrypted Data</returns>
		public static byte[] Encrypt(byte[] data, string pbKy)
		{
			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = 2048;

					//
					// reading public key
					rsa.FromXmlString(pbKy);

					//
					// performing encryption
					var encb = rsa.Encrypt(data, false);
					return encb;
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="data">Base64 formatted of Encrypted Data</param>
		/// <param name="prKy">RSA Private Key in Xml Format</param>
		/// <returns>Decrypted Data</returns>
		public static byte[] Decrypt(byte[] data, string prKy)
		{
			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = 2048;

					//
					// reading private key
					rsa.FromXmlString(prKy);

					//
					// performing decryption
					var decb = rsa.Decrypt(data, false);
					return decb;
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		#endregion

		/// <summary>
		/// 
		/// </summary>
		/// <param name="keySize"></param>
		/// <param name="pbStore">Public Key Store Path</param>
		/// <param name="prStore">Private Key Store Path</param>
		public static void Export(int keySize, string pbStore, string prStore)
		{
			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1,
					Flags = CspProviderFlags.UseArchivableKey,
					KeyNumber = (int)KeyNumber.Exchange,
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = keySize;

					//
					// persisting public key
					if (File.Exists(pbStore))
						File.Delete(pbStore);
					using (var pbWriter = new StreamWriter(pbStore))
					{
						pbWriter.Write(rsa.ToXmlString(false));
						pbWriter.Flush();
						pbWriter.Close();
					}

					//
					// persisting private key
					if (File.Exists(prStore))
						File.Delete(prStore);
					using (var prWriter = new StreamWriter(prStore))
					{
						prWriter.Write(rsa.ToXmlString(true));
						prWriter.Flush();
						prWriter.Close();
					}

					logger.Debug(rsa.SignatureAlgorithm);
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
			}
		}

		#region Cryptographer

		public byte[] Encrypt(byte[] sKey, byte[] data, bool hash = false)
		{
			throw new NotImplementedException();
		}

		public byte[] Decrypt(byte[] sKey, byte[] data, bool hash = false)
		{
			throw new NotImplementedException();
		}

		#endregion
	}
}