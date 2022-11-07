using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
	[TestFixture]
	public class TimeTest
	{
		[Test]
		public void CheckCmsTimeVsX509Time()
		{
			DateTime now = DateTime.UtcNow;

			// Time classes only have a resolution of seconds
			now = SimpleTest.MakeUtcDateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second);

            Cms.Time cmsTime = new Cms.Time(now);
			X509.Time x509Time = new X509.Time(now);

			Assert.AreEqual(now, cmsTime.ToDateTime());
			Assert.AreEqual(now, x509Time.ToDateTime());
		}
	}
}
