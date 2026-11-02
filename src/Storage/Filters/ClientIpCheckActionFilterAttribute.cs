#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Altinn.Platform.Storage.Filters;

/// <summary>
/// Action filter that only lets requests through when the connection's remote IP address
/// is an exact match for one of the addresses in the safelist.
/// </summary>
/// <remarks>
/// The remote address is taken from <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.RemoteIpAddress"/>.
/// Client supplied headers such as X-Forwarded-For are never read directly; when Storage runs
/// behind a reverse proxy, the forwarded headers middleware must be configured to set the
/// remote address from the trusted proxy. An empty safelist denies every request.
/// </remarks>
public class ClientIpCheckActionFilterAttribute : ActionFilterAttribute
{
    private HashSet<IPAddress> _safeList = [];

    /// <summary>
    /// Semicolon separated list of valid IP addresses
    /// </summary>
    public string Safelist
    {
        set { _safeList = ParseSafelist(value); }
    }

    /// <summary>
    /// Authorize from ip address
    /// </summary>
    /// <param name="context">context</param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        IPAddress remoteIp = context.HttpContext?.Connection.RemoteIpAddress;
        if (remoteIp is null || !_safeList.Contains(Normalize(remoteIp)))
        {
            context.Result = new ForbidResult();
            return;
        }

        base.OnActionExecuting(context);
    }

    private static HashSet<IPAddress> ParseSafelist(string value)
    {
        HashSet<IPAddress> safeList = [];
        IEnumerable<string> entries = (value ?? string.Empty).Split(
            ';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
        );

        foreach (string entry in entries)
        {
            if (
                !IPAddress.TryParse(entry, out IPAddress ipAddress)
                || (
                    ipAddress.AddressFamily == AddressFamily.InterNetwork
                    && entry.Count(c => c == '.') != 3
                )
            )
            {
                throw new FormatException($"Invalid IP address '{entry}' in IP safelist.");
            }

            safeList.Add(Normalize(ipAddress));
        }

        return safeList;
    }

    private static IPAddress Normalize(IPAddress ipAddress) =>
        ipAddress.IsIPv4MappedToIPv6 ? ipAddress.MapToIPv4() : ipAddress;
}
