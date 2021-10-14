/**
 * Copyright (C) moniüs, 2014.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

using System;
using System.Security.Cryptography;

namespace monius.Cryptography
{
	/// <summary>
	/// 
	/// </summary>
	internal sealed class AES : Cryptographer
	{
		private static readonly byte[] iV =
		{
			0x01, 0x09, 0x07, 0x06, 0x01, 0x03, 0x05, 0x04,
			0x11, 0x19, 0x17, 0x16, 0x11, 0x13, 0x15, 0x14
		};

		/// <summary>
		/// 
		/// </summary>
		public AES()
		{
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="securityKey"></param>
		public AES(string securityKey)
		{
			SecurityKey = securityKey;
		}

		/// <summary>
		/// Raw Symmectric Cryptography Key in Base64 format
		/// </summary>
		public string SecurityKey { get; private set; }

		#region Encrypt|Decrypt

		/// <summary>
		/// AES Encryption
		/// </summary>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		public byte[] Encrypt(byte[] data, bool hash = false)
		{
			if (string.IsNullOrEmpty(SecurityKey))
				throw new CommonCryptologyException(ResourceObjects.SecurityKeyIsNull);

			byte[] sKey = Convert.FromBase64String(SecurityKey);
			return Encrypt(sKey, data, hash);
		}

		/// <summary>
		/// AES Decryption
		/// </summary>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		public byte[] Decrypt(byte[] data, bool hash = false)
		{
			if (string.IsNullOrEmpty(SecurityKey))
				throw new CommonCryptologyException(ResourceObjects.SecurityKeyIsNull);

			byte[] sKey = Convert.FromBase64String(SecurityKey);
			return Decrypt(sKey, data, hash);
		}

		#endregion

		#region Encrypt|Decrypt

		/// <summary>
		/// AES Encryption
		/// </summary>
		/// <param name="sKey">Security Key</param>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		public byte[] Encrypt(byte[] sKey, byte[] data, bool hash = false)
		{
			//
			// checks if key length matches preferred key size
			if (sKey.Length != 16)
				throw new CommonCryptologyException(ResourceObjects.SecurityKeySizeIsNotCorrect);

			//
			// hashing the security key
			if (hash)
			{
				var md5 = new MD5CryptoServiceProvider();
				sKey = md5.ComputeHash(sKey);
				md5.Clear();
			}

			//
			// performing cryptography
			using (var cp = new RijndaelManaged())
			{
				cp.KeySize = 128;			// key size = 128 then
				cp.Key = sKey;				// key byte = 16 bytes (must be)
				cp.IV = iV;
				cp.Mode = CipherMode.CBC;
				cp.Padding = PaddingMode.PKCS7;

				var ct = cp.CreateEncryptor();
				var ra = ct.TransformFinalBlock(data, 0, data.Length);

				cp.Clear();

				return ra;
			}
		}

		/// <summary>
		/// AES Decryption
		/// </summary>
		/// <param name="sKey">Security Key</param>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		public byte[] Decrypt(byte[] sKey, byte[] data, bool hash = false)
		{
			//
			// checks if key length matches preferred key size
			if (sKey.Length != 16)
				throw new CommonCryptologyException(ResourceObjects.SecurityKeySizeIsNotCorrect);

			//
			// hashing the security key
			if (hash)
			{
				var md5 = new MD5CryptoServiceProvider();
				sKey = md5.ComputeHash(sKey);
				md5.Clear();
			}

			//
			// performing cryptography
			using (var cp = new RijndaelManaged())
			{
				cp.KeySize = 128;			// key size = 128 then
				cp.Key = sKey;				// key byte = 16 bytes (must be)
				cp.IV = iV;
				cp.Mode = CipherMode.CBC;
				cp.Padding = PaddingMode.PKCS7;

				var ct = cp.CreateDecryptor();
				var ra = ct.TransformFinalBlock(data, 0, data.Length);

				cp.Clear();

				return ra;
			}
		}

		#endregion
	}
}