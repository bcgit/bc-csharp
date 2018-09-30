using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Utilities.Test
{
    public abstract class SimpleTest
        : ITest
    {
		public abstract string Name
		{
			get;
		}

		private ITestResult Success()
        {
            return SimpleTestResult.Successful(this, "Okay");
        }

        internal void Fail(
            string message)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void Fail(
            string		message,
            Exception	throwable)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, throwable));
        }

		internal void Fail(
            string message,
            object expected,
            object found)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, expected, found));
        }

        internal void IsTrue(bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsTrue(string message, bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(object a, object b)
        {
            if (!a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsEquals(int a, int b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsEquals(string message, bool a, bool b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(string message, long a, long b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(string message, object a, object b)
        {
            if (a == null && b == null)
                return;

            if (a == null)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
            if (b == null)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
            if (!a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal bool AreEqual(
            byte[] a,
            byte[] b)
        {
			return Arrays.AreEqual(a, b);
		}

		public virtual ITestResult Perform()
        {
            try
            {
                PerformTest();

				return Success();
            }
            catch (TestFailedException e)
            {
                return e.GetResult();
            }
            catch (Exception e)
            {
                return SimpleTestResult.Failed(this, "Exception: " +  e, e);
            }
        }

		internal static void RunTest(
            ITest test)
        {
            RunTest(test, Console.Out);
        }

		internal static void RunTest(
            ITest		test,
            TextWriter	outStream)
        {
            ITestResult result = test.Perform();

			outStream.WriteLine(result.ToString());
            if (result.GetException() != null)
            {
                outStream.WriteLine(result.GetException().StackTrace);
            }
        }

		internal static Stream GetTestDataAsStream(
			string name)
		{
			string fullName = GetFullName(name);
            
			return typeof(SimpleTest).GetTypeInfo().Assembly.GetManifestResourceStream(fullName);
		}

		internal static string[] GetTestDataEntries(
			string prefix)
		{
			string fullPrefix = GetFullName(prefix);

			ArrayList result = new ArrayList();
			string[] fullNames = typeof(SimpleTest).GetTypeInfo().Assembly.GetManifestResourceNames();
			foreach (string fullName in fullNames)
			{
				if (fullName.StartsWith(fullPrefix))
				{
					string name = GetShortName(fullName);
					result.Add(name);
				}
			}
			return (string[])result.ToArray(typeof(String));
		}

		private static string GetFullName(
			string name)
		{
            return "crypto.test.data." + name;
		}

		private static string GetShortName(
			string fullName)
		{
            return fullName.Substring("crypto.test.data.".Length);
		}

#if NETCF_1_0 || NETCF_2_0
		private static string GetNewLine()
		{
			MemoryStream buf = new MemoryStream();
			StreamWriter w = new StreamWriter(buf, Encoding.ASCII);
			w.WriteLine();
			w.Close();
			byte[] bs = buf.ToArray();
			return Encoding.ASCII.GetString(bs, 0, bs.Length);
		}

		internal static string GetEnvironmentVariable(
			string variable)
		{
			return null;
		}
#else
		private static string GetNewLine()
		{
			return Environment.NewLine;
		}
#endif

		internal static readonly string NewLine = GetNewLine();

		public abstract void PerformTest();

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second)
        {
#if PORTABLE
            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
#else
            return new DateTime(year, month, day, hour, minute, second);
#endif
        }

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond)
        {
#if PORTABLE
            return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
#else
            return new DateTime(year, month, day, hour, minute, second, millisecond);
#endif
        }
    }
}
