using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace trout.models
{
    public class ADObject
    {
        public string distinguishedName { get; set; }
        public string sid {  get; set; }
        public string name { get; set; }

        public override string ToString()
        {
            return this.name;
        }
    }
}
