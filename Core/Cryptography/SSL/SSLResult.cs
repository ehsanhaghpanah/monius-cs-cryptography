/**
 * Copyright (C) moniüs, 2017.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

namespace monius.Cryptography.SSL
{
	/// <summary>
	/// SSLResult
	/// </summary>
	public sealed class SSLResult
	{
		/// <summary>
		/// raw random AES key
		/// </summary>
		public string RawCipherKy { get; set; }

		/// <summary>
		/// random AES key ciphered by RSA
		/// </summary>
		public string SymmetricKy { get; set; }

		/// <summary>
		/// message body ciphered by AES
		/// </summary>
		public string MessageBody { get; set; }
	}
}