using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;

using NUnit.Framework;

namespace Study.CSharp.Libraries
{
    [TestFixture]
    public sealed class DateTimeStudy
    {
        [Test]
        public void ParseExact_Study()
        {
            var result = DateTime.ParseExact("2012年01月01日", "yyyy年MM月dd日", null, DateTimeStyles.None);

            Assert.AreEqual(result, new DateTime(2012, 01, 01));
        }
    }
}
