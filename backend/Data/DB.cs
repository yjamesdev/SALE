using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.General;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace backend.Data
{
    public class DB : IdentityDbContext<IdentityUser>
    {
        public DB(DbContextOptions options) : base(options)
        {
          
        }
    }
}