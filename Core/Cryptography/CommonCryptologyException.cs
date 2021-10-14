/**
 * Copyright (C) moniüs, 2014.
 * All rights reserved.
 * E. Haghpanah; haghpanah@monius.net
 */

using System;
using System.Runtime.Serialization;

namespace monius.Cryptography
{
	/// <summary>
	/// CommonCryptologyException
	/// </summary>
	[Serializable]
	public sealed class CommonCryptologyException : Base.Exception
	{
		/// <summary>
		/// 
		/// </summary>
		public CommonCryptologyException()
			: this(string.Empty, null)
		{
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="message"></param>
		public CommonCryptologyException(string message)
			: this(message, null)
		{
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="message"></param>
		/// <param name="inner"></param>
		public CommonCryptologyException(string message, Exception inner)
			: base(message, inner)
		{
			OpCode = 0x0053;
		}

		/// <summary>
		/// as this exception is sealed, so it is marked as private
		/// </summary>
		/// <param name="info"></param>
		/// <param name="context"></param>
		private CommonCryptologyException(SerializationInfo info, StreamingContext context)
			: base(info, context)
		{
		}
	}
}