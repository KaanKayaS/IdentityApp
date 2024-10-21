using IdentityApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<IEmailSender, SmtpEmailSender>(i =>
     new SmtpEmailSender(
        builder.Configuration["EmailSender:Host"],
        builder.Configuration.GetValue<int>("EmailSender:Port"),
        builder.Configuration.GetValue<bool>("EmailSender:EnableSSL"),
        builder.Configuration["EmailSender:Username"],
        builder.Configuration["EmailSender:Password"])
     );
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<IdentityContext>(
    options => options.UseSqlServer(builder.Configuration["ConnectionStrings:mssql_connection"]));

builder.Services.AddIdentity<AppUser, AppRole>().AddEntityFrameworkStores<IdentityContext>().AddDefaultTokenProviders();  // token providerı email onaylaması için ekledik

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireDigit = false;

    options.User.RequireUniqueEmail = true;
    //   options.User.AllowedUserNameCharacters= "abcdefghijklmnopqrstuvwxyz";

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // eğer 5 kez yanlış girdiyse kullanıcının hesabını 5 dk kitler.
    options.Lockout.MaxFailedAccessAttempts = 5;                     // kullanıcının yanlış girmek için 5 hakkı var 

    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";                        // defaultu bu zaten yazmasakta olur farklı bir controller altına yönlendirceksek login için bu kısımdan yapılıyor.
    options.AccessDeniedPath = "/Account/AccessDenied";         // uygulamaya login oldun fakat rolünden dolayı erişimin yok nereye yönlendirceğini belirtiyor
    options.SlidingExpiration = true;                           // uygulamaya girdiğinde cookienin otomatik silinmesine 15 gün varsa bu true olduğu için yine 30 güne geri çıkacaka
    options.ExpireTimeSpan = TimeSpan.FromDays(30);            // uygulamada cookien 30 gün boyunca durucak sonra silinicek
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication(); // kimlik doğrulama için burda tanımlıyor olmamız gerekli

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

IdentitySeedData.IdentityTestUser(app);

app.Run();
