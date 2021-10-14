/**
 * Copyright (C) moniüs, 2017.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

namespace monius.Cryptography
{
	/// <summary>
	/// Cryptographer
	/// </summary>
	public interface Cryptographer
	{
		/// <summary>
		/// Encryption
		/// </summary>
		/// <param name="sKey">Security Key</param>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		byte[] Encrypt(byte[] sKey, byte[] data, bool hash = false);

		/// <summary>
		/// Decryption
		/// </summary>
		/// <param name="sKey">Security Key</param>
		/// <param name="data">Data</param>
		/// <param name="hash">A flag indicates that Security Key must be hashed before cryptography</param>
		/// <returns></returns>
		byte[] Decrypt(byte[] sKey, byte[] data, bool hash = false);
	}
}