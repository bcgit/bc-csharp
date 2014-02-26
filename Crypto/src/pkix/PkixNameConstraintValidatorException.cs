using System;

namespace Org.BouncyCastle.Pkix
{
    public class PkixNameConstraintValidatorException : Exception
    {
        public PkixNameConstraintValidatorException(String msg)
            : base(msg)
        {
        }
    }
}
