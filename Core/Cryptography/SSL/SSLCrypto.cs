/**
 * Copyright (C) moniüs, 2017.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

using System;

namespace monius.Cryptography.SSL
{
	/// <summary>
	/// SSLCrypto
	/// </summary>
	public static class SSLCrypto
	{
		private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text"></param>
		/// <returns></returns>
		public static SSLResult Encrypt(string text)
		{
			return Encrypt(ResourceObjects.RsaPbKey, text);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="pbKy">an xml string containing rsa public key parameters</param>
		/// <param name="text"></param>
		/// <returns></returns>
		public static SSLResult Encrypt(string pbKy, string text)
		{
			try
			{
				//
				// generate an AES 128 random key as Kaes
				var rawKy = Guid.NewGuid().ToString().Replace("-", "").Substring(4, 16);

				//
				// encrypt Kaes using RSA as SK in http header (in base 64)
				var symKy = Helper.RSACrypto.Encrypt(pbKy, rawKy);

				//
				// encrypt text using AES and Kaes in http body (in base 64)
				var mBody = Helper.AESCrypto.Encrypt(rawKy, text);

				return new SSLResult
				{
					SymmetricKy = symKy,
					MessageBody = mBody

				};
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
		/// <param name="data"></param>
		/// <returns></returns>
		public static string Decrypt(SSLResult data)
		{
			return Decrypt(ResourceObjects.RsaPrKey, data);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prKy">an xml string containing rsa private key parameters</param>
		/// <param name="data"></param>
		/// <returns></returns>
		public static string Decrypt(string prKy, SSLResult data)
		{
			try
			{
				//
				// decrypt Kaes using RSA
				var rawKy = Helper.RSACrypto.Decrypt(prKy, data.SymmetricKy);

				//
				// decrypt data body using AES
				return Helper.AESCrypto.Decrypt(rawKy, data.MessageBody);
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
		/// <param name="data"></param>
		/// <returns></returns>
		public static string GetSymmetricKey(SSLResult data)
		{
			return GetSymmetricKey(ResourceObjects.RsaPrKey, data);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="prKy">an xml string containing rsa private key parameters</param>
		/// <param name="data"></param>
		/// <returns></returns>
		public static string GetSymmetricKey(string prKy, SSLResult data)
		{
			try
			{
				//
				// decrypt Kaes using RSA
				return Helper.RSACrypto.Decrypt(prKy, data.SymmetricKy);
			}
			catch (Exception p)
			{
				logger.Error(p);
				return null;
			}
		}
	}
}