using UsbGuard.Service;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "UsbGuard");
builder.Services.AddSingleton<ClamClient>();
builder.Services.AddSingleton<GuardWorker>();
builder.Services.AddHostedService(services => services.GetRequiredService<GuardWorker>());
builder.Services.AddHostedService<ControlServer>();

await builder.Build().RunAsync();
