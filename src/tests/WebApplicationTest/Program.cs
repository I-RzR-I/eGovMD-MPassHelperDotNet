// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.WebApplicationTest
//  Author           : RzR
//  Created On       : 2023-06-25 01:34
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-30 14:07
// ***********************************************************************
//  <copyright file="Program.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

#endregion

namespace WebApplicationTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder => { webBuilder.UseStartup<Startup>(); });
        }
    }
}