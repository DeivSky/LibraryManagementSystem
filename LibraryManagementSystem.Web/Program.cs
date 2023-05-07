using LibraryManagementSystem.Web.Areas.Identity;
using LibraryManagementSystem.Web.Data;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
	{
		options.SignIn.RequireConfirmedAccount = true;
		options.User.RequireUniqueEmail = true;
	})
	.AddRoles<IdentityRole>()
	.AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<IdentityUser>>();
builder.Services.AddSingleton<WeatherForecastService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseMigrationsEndPoint();
}
else
{
	app.UseExceptionHandler("/Error");
	// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
	app.UseHsts();
}
app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllers();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

using (var scope = app.Services.CreateScope())
{
	await CreateRoles(scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>());
	await CreateAdmin(scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>());
}

app.Run();


async Task CreateRoles(RoleManager<IdentityRole> roleManager)
{
	string[] roles = { "Admin", "User", "Librarian" };

	foreach (var role in roles)
		if (!await roleManager.RoleExistsAsync(role))
			await roleManager.CreateAsync(new IdentityRole(role));
}

async Task CreateAdmin(UserManager<IdentityUser> userManager)
{
	var adminUsers = await userManager.GetUsersInRoleAsync("Admin");
	if (adminUsers is not null && adminUsers.Count > 0)
		return;

	Console.WriteLine($"Administrator user doesn't exist, creating...");

	IdentityUser adminUser;
	IdentityResult? result;
	do
	{
		Thread.Sleep(500);
		string email = AskWhileEmpty("Admin email: ");
		string password = AskWhileEmpty("Admin password: ");

		adminUser = new(email) { Email = email };

		result = await userManager.CreateAsync(adminUser, password);
		if (!result.Succeeded)
		{
			foreach (var error in result.Errors)
				Console.WriteLine($"Error {error.Code}: {error.Description}");
		}
	} while (!result.Succeeded);

	var token = await userManager.GenerateEmailConfirmationTokenAsync(adminUser);
	await userManager.ConfirmEmailAsync(adminUser, token);

	await userManager.AddToRoleAsync(adminUser, "Admin");

	Console.WriteLine($"Created administrator user \"{adminUser.UserName}\".");
}

string AskWhileEmpty(string question)
{
	string? result;
	do
	{
		Console.Write(question);
		result = Console.ReadLine();
	} while (string.IsNullOrEmpty(result));

	return result;
}