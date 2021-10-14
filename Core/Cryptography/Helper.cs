/**
 * Copyright (C) moniüs, 2017.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

using System;
using System.Security.Cryptography;
using System.Text;

namespace monius.Cryptography
{
	/// <summary>
	/// Helper
	/// </summary>
	static public class Helper
	{
		private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

		public static class DESCrypto
		{
			/// <summary>
			/// 
			/// </summary>
			/// <param name="sKey">raw plain key as string</param>
			/// <param name="text">raw plain data</param>
			/// <returns>base 64 encrypted data</returns>
			public static string Encrypt(string sKey, string text)
			{
				try
				{
					byte[] bKey = Encoding.UTF8.GetBytes(sKey);
					byte[] data = Encoding.UTF8.GetBytes(text);

					DES crypto = new DES();
					return Convert.ToBase64String(crypto.Encrypt(bKey, data));
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
			/// <param name="sKey">raw plain key as string</param>
			/// <param name="bs64">ciphered data in base 64 format</param>
			/// <returns>raw plain data</returns>
			public static string Decrypt(string sKey, string bs64)
			{
				try
				{
					byte[] bKey = Encoding.UTF8.GetBytes(sKey);
					byte[] data = Convert.FromBase64String(bs64);

					DES crypto = new DES();
					return Encoding.UTF8.GetString(crypto.Decrypt(bKey, data));
				}
				catch (Exception p)
				{
					logger.Error(p);
					return null;
				}
			}
		}

		public static class AESCrypto
		{
			/// <summary>
			/// 
			/// </summary>
			/// <param name="sKey">raw plain key as string</param>
			/// <param name="text">raw plain data</param>
			/// <returns>base 64 encrypted data</returns>
			public static string Encrypt(string sKey, string text)
			{
				try
				{
					byte[] bKey = Encoding.UTF8.GetBytes(sKey);
					byte[] data = Encoding.UTF8.GetBytes(text);

					AES crypto = new AES();
					return Convert.ToBase64String(crypto.Encrypt(bKey, data));
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
			/// <param name="sKey">raw plain key as string</param>
			/// <param name="bs64">ciphered data in base 64 format</param>
			/// <returns>raw plain data</returns>
			public static string Decrypt(string sKey, string bs64)
			{
				try
				{
					byte[] bKey = Encoding.UTF8.GetBytes(sKey);
					byte[] data = Convert.FromBase64String(bs64);

					AES crypto = new AES();
					return Encoding.UTF8.GetString(crypto.Decrypt(bKey, data));
				}
				catch (Exception p)
				{
					logger.Error(p);
					return null;
				}
			}
		}

		public static class RSACrypto
		{
			/// <summary>
			/// 
			/// </summary>
			/// <param name="text"></param>
			/// <returns></returns>
			public static string Encrypt(string text)
			{
				return Encrypt(ResourceObjects.RsaPbKey, text);
			}

			/// <summary>
			/// 
			/// </summary>
			/// <param name="pbKy">an xml string containing rsa public key parameters</param>
			/// <param name="text"></param>
			/// <returns></returns>
			public static string Encrypt(string pbKy, string text)
			{
				try
				{
					var data = Encoding.UTF8.GetBytes(text);
					var encb = RSA.Encrypt(data, pbKy);
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
			/// <param name="bs64"></param>
			/// <returns></returns>
			public static string Decrypt(string bs64)
			{
				return Decrypt(ResourceObjects.RsaPrKey, bs64);
			}

			/// <summary>
			/// 
			/// </summary>
			/// <param name="prKy">an xml string containing rsa private key parameters</param>
			/// <param name="bs64"></param>
			/// <returns></returns>
			public static string Decrypt(string prKy, string bs64)
			{
				try
				{
					var data = Convert.FromBase64String(bs64);
					var decb = RSA.Decrypt(data, prKy);
					var text = Encoding.UTF8.GetString(decb);
					return text;
				}
				catch (Exception p)
				{
					logger.Error(p);
					return null;
				}
			}
		}

		#region 

		/// <summary>
		/// 
		/// </summary>
		/// <param name="m">Modulus in Base 64</param>
		/// <param name="e">Exponent in Base 64</param>
		/// <param name="text">Plain Text</param>
		/// <returns></returns>
		public static string Encrypt(string m, string e, string text)
		{
			//const string mod_v = "wfuunkpLxn5d5csNRRUBsWnkBSlRCJWqd99Exbuqq2HvL+gAKc4dNbNIdfosCh5Kdjgei9O92oG3oq6zhjfPgPN4m6aOoM3o1Ho+EAqmWSP3sBqaCmS9bD/vpIc/+uSQaUj56TC+xj1ed+5hWJ6e2+/JWV3kFO8mIHJHWTL2RiE=";
			//const string exp_v = "AQAB";

			try
			{
				var csp = new CspParameters
				{
					ProviderType = 1
				};
				using (var rsa = new RSACryptoServiceProvider(csp))
				{
					rsa.KeySize = 2048;

					byte[] mod_b = Convert.FromBase64String(m);
					byte[] exp_b = Convert.FromBase64String(e);
					var paramz = new RSAParameters
					{
						Modulus = mod_b,
						Exponent = exp_b
					};

					//
					// reading public key
					rsa.ImportParameters(paramz);

					//
					// performing encryption
					var data = Encoding.UTF8.GetBytes(text);
					var encb = rsa.Encrypt(data, false);
					var bs64 = Convert.ToBase64String(encb);
					return bs64;
				}
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}

		#endregion
	}
}